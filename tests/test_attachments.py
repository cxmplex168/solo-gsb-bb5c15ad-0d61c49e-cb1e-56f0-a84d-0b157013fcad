"""事件证据附件测试。

覆盖：流式上传（PDF/JPEG/PNG 校验、10 MiB 上限）、SHA-256 内容寻址去重、
每次上传独立记录、下载前复算（缺失 / 篡改 -> 409 且列表标损）、完整性刷新
恢复、删除引用计数（最后引用才清理实体）、有关联附件的事件 / 样本禁止删除、
报告仅列附件元数据。
"""
from __future__ import annotations

import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-attachment-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_attachments.db")
os.environ["ATTACHMENT_DIR"] = os.path.join(_tmp, "attachments")

import hashlib
import itertools

import pytest
from fastapi.testclient import TestClient

from app.attachments import attachment_dir
from app.db import get_connection, init_db
from app.main import app


@pytest.fixture(scope="module")
def client():
    init_db()
    with TestClient(app) as c:
        yield c


_seq = itertools.count(1)


@pytest.fixture()
def sample(client):
    code = f"UT-ATTACH-{next(_seq):03d}"
    resp = client.post(
        "/api/samples",
        json={"code": code, "name": "证据附件测试样本", "description": ""},
    )
    assert resp.status_code == 201
    return resp.json()


@pytest.fixture()
def event(client, sample):
    resp = client.post(
        f"/api/samples/{sample['id']}/events",
        json={"custodian": "张三", "start_time": "2026-09-18 09:00:00",
              "end_time": "2026-09-18 10:00:00"},
    )
    assert resp.status_code == 201
    return resp.json()


PDF_BYTES = b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog >>\nendobj\n"
PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPEG_BYTES = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"\x01" * 32


def _upload(client, event_id, content, filename="证据.pdf",
            content_type="application/pdf", uploaded_by="审计员 王敏"):
    return client.post(
        f"/api/events/{event_id}/attachments",
        files={"file": (filename, content, content_type)},
        data={"uploaded_by": uploaded_by},
    )


def test_upload_pdf_and_metadata(client, event):
    resp = _upload(client, event["id"], PDF_BYTES, filename="交接单 证据.pdf")
    assert resp.status_code == 201, resp.text
    a = resp.json()
    assert a["event_id"] == event["id"]
    assert a["filename"] == "交接单 证据.pdf"
    assert a["size"] == len(PDF_BYTES)
    assert a["size_text"]
    assert a["media_type"] == "application/pdf"
    assert a["uploaded_by"] == "审计员 王敏"
    assert a["uploaded_at"]
    assert a["status"] == "ok"
    assert a["digest"] == hashlib.sha256(PDF_BYTES).hexdigest()
    assert len(a["digest"]) == 64

    listing = client.get(f"/api/events/{event['id']}/attachments").json()
    assert len(listing) == 1
    assert listing[0]["id"] == a["id"]


def test_upload_jpeg_png(client, event):
    r1 = _upload(client, event["id"], JPEG_BYTES, "a.jpg", "image/jpeg", "李四")
    assert r1.status_code == 201, r1.text
    assert r1.json()["media_type"] == "image/jpeg"
    r2 = _upload(client, event["id"], PNG_BYTES, "b.png", "image/png", "李四")
    assert r2.status_code == 201, r2.text
    assert r2.json()["media_type"] == "image/png"


@pytest.mark.parametrize(
    "content,filename,ct",
    [
        (b"plain text not pdf", "x.pdf", "application/pdf"),       # 魔数不符
        (PDF_BYTES, "x.txt", "text/plain"),                       # 扩展名不符
        (PDF_BYTES, "x.pdf", "text/plain"),                       # 声明类型不符
        (b"", "x.pdf", "application/pdf"),                        # 空文件
        (b"GIF89a" + b"x" * 10, "x.gif", "image/gif"),            # 不支持的类型
    ],
)
def test_upload_rejections(client, event, content, filename, ct):
    resp = _upload(client, event["id"], content, filename, ct)
    assert resp.status_code in (415, 422), resp.text


def test_upload_size_limit(client, event):
    big = b"%PDF" + b"\n" * (10 * 1024 * 1024)
    resp = _upload(client, event["id"], big, "big.pdf")
    assert resp.status_code == 413, resp.text


def test_upload_to_nonexistent_event(client, sample):
    resp = _upload(client, 999999, PDF_BYTES)
    assert resp.status_code == 404


def test_upload_missing_uploaded_by(client, event):
    resp = client.post(
        f"/api/events/{event['id']}/attachments",
        files={"file": ("x.pdf", PDF_BYTES, "application/pdf")},
    )
    assert resp.status_code == 422


def test_content_addressing_dedup_but_independent_records(client, sample):
    e1 = client.post(
        f"/api/samples/{sample['id']}/events",
        json={"custodian": "甲", "start_time": "2026-09-18 09:00:00"},
    ).json()
    e2 = client.post(
        f"/api/samples/{sample['id']}/events",
        json={"custodian": "乙", "start_time": "2026-09-18 11:00:00"},
    ).json()

    r1 = _upload(client, e1["id"], PDF_BYTES, "first.pdf", uploaded_by="甲")
    r2 = _upload(client, e2["id"], PDF_BYTES, "second-改名.pdf", uploaded_by="乙")
    assert r1.status_code == 201 and r2.status_code == 201
    a1, a2 = r1.json(), r2.json()
    # 相同内容：同一 blob 实体
    assert a1["digest"] == a2["digest"]
    # 每次上传独立记录
    assert a1["id"] != a2["id"]
    assert a1["filename"] != a2["filename"]
    assert a1["uploaded_by"] == "甲" and a2["uploaded_by"] == "乙"

    digest = a1["digest"]
    # blob 表只有一个实体
    conn = get_connection()
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM attachment_blobs WHERE digest = ?", (digest,)
        ).fetchone()[0]
        assert n == 1
    finally:
        conn.close()


def _blob_file(digest: str):
    return attachment_dir() / digest[:2] / digest[2:4] / digest


def test_download_verifies_digest(client, event):
    a = _upload(client, event["id"], PNG_BYTES, "ok.png", "image/png").json()
    resp = client.get(f"/api/attachments/{a['id']}/download")
    assert resp.status_code == 200
    assert resp.content == PNG_BYTES
    cd = resp.headers["content-disposition"]
    assert "ok.png" in cd
    assert "attachment" in cd


def test_download_missing_blob_returns_409_and_marks_corrupt(client, sample, event):
    a = _upload(client, event["id"], PNG_BYTES, "gone.png", "image/png").json()
    _blob_file(a["digest"]).unlink()

    resp = client.get(f"/api/attachments/{a['id']}/download")
    assert resp.status_code == 409
    assert "完整性" in resp.json()["detail"]

    listing = client.get(f"/api/events/{event['id']}/attachments").json()
    target = next(x for x in listing if x["id"] == a["id"])
    assert target["status"] == "corrupt"
    assert target["corruption_reason"] == "missing"

    # 样本详情同样带出损坏标记
    detail = client.get(f"/api/samples/{sample['id']}").json()
    target = next(x for x in detail["attachments"] if x["id"] == a["id"])
    assert target["status"] == "corrupt"



def test_download_tampered_blob_returns_409(client, event):
    a = _upload(client, event["id"], PNG_BYTES, "tamper.png", "image/png").json()
    path = _blob_file(a["digest"])
    path.write_bytes(PNG_BYTES + b"tampered")
    resp = client.get(f"/api/attachments/{a['id']}/download")
    assert resp.status_code == 409
    listing = client.get(f"/api/events/{event['id']}/attachments").json()
    target = next(x for x in listing if x["id"] == a["id"])
    assert target["status"] == "corrupt"
    assert target["corruption_reason"] == "digest_mismatch"

    # 恢复内容后刷新 -> 恢复正常，再次下载成功
    path.write_bytes(PNG_BYTES)
    refreshed = client.post(f"/api/attachments/{a['id']}/refresh")
    assert refreshed.status_code == 200
    assert refreshed.json()["status"] == "ok"
    assert client.get(f"/api/attachments/{a['id']}/download").status_code == 200


def test_event_level_refresh(client, event):
    a = _upload(client, event["id"], PDF_BYTES, "x.pdf").json()
    _blob_file(a["digest"]).unlink()
    resp = client.post(f"/api/events/{event['id']}/attachments/refresh")
    assert resp.status_code == 200
    target = next(x for x in resp.json() if x["id"] == a["id"])
    assert target["status"] == "corrupt"


def test_delete_reference_counting(client, sample):
    # 使用本测试独有的内容，避免与其他用例上传的相同 blob 共享引用计数
    unique_pdf = b"%PDF-1.4\nrefcount-unique-" + os.urandom(16)
    e1 = client.post(
        f"/api/samples/{sample['id']}/events",
        json={"custodian": "甲", "start_time": "2026-09-18 09:00:00"},
    ).json()
    e2 = client.post(
        f"/api/samples/{sample['id']}/events",
        json={"custodian": "乙", "start_time": "2026-09-18 11:00:00"},
    ).json()
    a1 = _upload(client, e1["id"], unique_pdf, "one.pdf").json()
    a2 = _upload(client, e2["id"], unique_pdf, "two.pdf").json()
    assert a1["digest"] == a2["digest"]
    blob = _blob_file(a1["digest"])
    assert blob.exists()

    # 删除第一条引用：实体保留
    assert client.delete(f"/api/attachments/{a1['id']}").status_code == 204
    assert blob.exists()
    assert client.get(f"/api/attachments/{a1['id']}/download").status_code == 404

    # 删除最后一个引用：实体清理
    assert client.delete(f"/api/attachments/{a2['id']}").status_code == 204
    assert not blob.exists()
    # 分片目录被清理（根目录保留）
    conn = get_connection()
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM attachment_blobs WHERE digest = ?", (a1["digest"],)
        ).fetchone()[0]
        assert n == 0
    finally:
        conn.close()
    assert attachment_dir().exists()


def test_delete_attachment_404(client):
    assert client.delete("/api/attachments/999999").status_code == 404


def test_event_with_attachments_cannot_be_deleted(client, event):
    _upload(client, event["id"], PDF_BYTES, "keep.pdf")
    resp = client.delete(f"/api/events/{event['id']}")
    assert resp.status_code == 409
    # 事件仍在
    assert client.get("/api/samples").status_code == 200


def test_sample_with_attachments_cannot_be_deleted(client, sample, event):
    _upload(client, event["id"], PDF_BYTES, "keep.pdf")
    resp = client.delete(f"/api/samples/{sample['id']}")
    assert resp.status_code == 409
    # 附件清理后允许删除（级联清除事件）
    a = client.get(f"/api/events/{event['id']}/attachments").json()[0]
    assert client.delete(f"/api/attachments/{a['id']}").status_code == 204
    assert client.delete(f"/api/samples/{sample['id']}").status_code == 204


def test_reports_list_only_metadata(client, sample, event):
    a = _upload(client, event["id"], PDF_BYTES, "报告中的证据.pdf").json()
    md = client.get(f"/api/samples/{sample['id']}/report?format=markdown")
    assert md.status_code == 200
    assert "事件证据附件" in md.text
    assert "报告中的证据.pdf" in md.text
    assert a["digest"] in md.text
    # 不含文件内容 / 下载地址
    assert "/api/attachments/" not in md.text
    assert "%PDF" not in md.text

    html_resp = client.get(f"/api/samples/{sample['id']}/report?format=html")
    assert html_resp.status_code == 200
    assert "事件证据附件" in html_resp.text
    assert "报告中的证据.pdf" in html_resp.text

    payload = client.get(
        f"/api/samples/{sample['id']}/report?format=json"
    ).json()
    atts = payload["attachments"]
    assert len(atts) == 1
    assert set(atts[0].keys()) == {
        "id", "event_id", "filename", "size", "size_text", "media_type",
        "uploaded_by", "uploaded_at", "sha256", "status",
        "corruption_reason", "last_verified_at",
    }
    assert atts[0]["sha256"] == a["digest"]


def test_sample_detail_includes_attachments(client, sample, event):
    _upload(client, event["id"], PDF_BYTES, "detail.pdf")
    detail = client.get(f"/api/samples/{sample['id']}").json()
    assert "attachments" in detail
    assert any(x["filename"] == "detail.pdf" for x in detail["attachments"])
