"""事件证据附件测试。

覆盖：上传（PDF/JPEG/PNG、类型与大小校验）、内容寻址去重（相同内容一份实体、
独立附件记录）、下载前复算摘要（缺失 / 篡改 -> 409 并标记损坏）、完整性刷新、
删除记录与实体引用计数回收、关联附件事件禁止删除、样本删除级联清理、
三种报告的附件元数据。
"""
from __future__ import annotations

import hashlib
import itertools
import os
import tempfile

_tmp = tempfile.mkdtemp(prefix="audit-attachment-tests-")
os.environ["AUDIT_DB_PATH"] = os.path.join(_tmp, "test_attachments.db")
os.environ["AUDIT_ATTACHMENT_DIR"] = os.path.join(_tmp, "attachments")

import pytest
from fastapi.testclient import TestClient

from app import attachments as att
from app.db import init_db
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
        json={"code": code, "name": "附件测试样本", "description": "证据附件"},
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


def _pdf(tag: bytes = b"") -> bytes:
    return b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n" + tag + b"\n%%EOF\n"


def _png(tag: bytes = b"") -> bytes:
    return b"\x89PNG\r\n\x1a\n" + b"\x00" * 32 + tag


def _jpeg(tag: bytes = b"") -> bytes:
    return b"\xff\xd8\xff\xe0\x00\x10JFIF" + b"\x00" * 16 + tag


def _upload(client, event_id, filename, content, uploader="李四", mime="application/pdf"):
    return client.post(
        f"/api/events/{event_id}/attachments",
        files={"file": (filename, content, mime)},
        data={"uploaded_by": uploader},
    )


def _attachments(client, sample_id):
    return client.get(f"/api/samples/{sample_id}").json()["attachments"]


# ---------- 上传与下载 ----------

def test_upload_and_download_roundtrip(client, sample, event):
    content = _pdf(b"roundtrip")
    resp = _upload(client, event["id"], "交接单.pdf", content, uploader="王五")
    assert resp.status_code == 201
    rec = resp.json()
    assert rec["filename"] == "交接单.pdf"
    assert rec["content_type"] == "application/pdf"
    assert rec["kind"] == "PDF"
    assert rec["size"] == len(content)
    assert rec["sha256"] == hashlib.sha256(content).hexdigest()
    assert rec["uploaded_by"] == "王五"
    assert rec["integrity"] == "ok"
    assert rec["event_id"] == event["id"]

    # 样本详情携带附件元数据
    atts = _attachments(client, sample["id"])
    assert [a["id"] for a in atts] == [rec["id"]]
    assert atts[0]["event_seq"] == 1
    assert atts[0]["event_custodian"] == "张三"

    # 下载：内容一致、文件名保留
    dl = client.get(f"/api/attachments/{rec['id']}/download")
    assert dl.status_code == 200
    assert dl.content == content
    assert dl.headers["content-type"] == "application/pdf"
    assert "attachment" in dl.headers["content-disposition"]


def test_upload_png_and_jpeg(client, sample, event):
    r1 = _upload(client, event["id"], "照片.png", _png(b"a"), mime="image/png")
    assert r1.status_code == 201
    assert r1.json()["content_type"] == "image/png"
    r2 = _upload(client, event["id"], "签收.jpg", _jpeg(b"b"), mime="image/jpeg")
    assert r2.status_code == 201
    assert r2.json()["content_type"] == "image/jpeg"


def test_upload_rejects_bad_type_empty_and_oversize(client, sample, event):
    # 非 PDF/JPEG/PNG（按魔数嗅探，扩展名伪装无效）
    bad = _upload(client, event["id"], "伪装.pdf", b"hello world, not a pdf")
    assert bad.status_code == 415

    empty = _upload(client, event["id"], "空.pdf", b"")
    assert empty.status_code == 400

    big = _pdf() + b"\x00" * (10 * 1024 * 1024)  # 超过 10 MiB
    oversize = _upload(client, event["id"], "超大.pdf", big)
    assert oversize.status_code == 413

    # 上传人必填
    no_uploader = client.post(
        f"/api/events/{event['id']}/attachments",
        files={"file": ("a.pdf", _pdf(), "application/pdf")},
        data={"uploaded_by": "  "},
    )
    assert no_uploader.status_code == 422

    # 事件不存在
    missing = _upload(client, 999999, "a.pdf", _pdf())
    assert missing.status_code == 404

    assert _attachments(client, sample["id"]) == []


# ---------- 内容寻址去重与引用计数回收 ----------

def test_dedup_same_content_single_blob(client, sample, event):
    content = _pdf(b"dedup-marker")
    r1 = _upload(client, event["id"], "第一版.pdf", content)
    r2 = _upload(client, event["id"], "第二版.pdf", content, uploader="赵六")
    assert r1.status_code == 201 and r2.status_code == 201
    a1, a2 = r1.json(), r2.json()

    # 每次上传保留独立记录，摘要相同
    assert a1["id"] != a2["id"]
    assert a1["sha256"] == a2["sha256"]
    assert a1["filename"] == "第一版.pdf" and a2["filename"] == "第二版.pdf"
    assert a2["uploaded_by"] == "赵六"

    # 相同内容只存一份实体（内容寻址路径唯一 + 实体表仅一行）
    blob = att.blob_path(a1["sha256"])
    assert os.path.exists(blob)
    from app.db import get_connection

    conn = get_connection()
    try:
        blob_rows = conn.execute(
            "SELECT COUNT(*) FROM attachment_blobs WHERE sha256 = ?",
            (a1["sha256"],),
        ).fetchone()[0]
        ref_rows = conn.execute(
            "SELECT COUNT(*) FROM attachments WHERE sha256 = ?",
            (a1["sha256"],),
        ).fetchone()[0]
    finally:
        conn.close()
    assert blob_rows == 1
    assert ref_rows == 2

    # 删除一条记录：实体仍被另一记录引用，保留
    assert client.delete(f"/api/attachments/{a1['id']}").status_code == 204
    assert os.path.exists(blob)
    dl = client.get(f"/api/attachments/{a2['id']}/download")
    assert dl.status_code == 200 and dl.content == content

    # 最后一个引用移除后才清理实体
    assert client.delete(f"/api/attachments/{a2['id']}").status_code == 204
    assert not os.path.exists(blob)
    assert client.delete(f"/api/attachments/{a2['id']}").status_code == 404


# ---------- 下载前复算与完整性刷新 ----------

def test_download_detects_tamper_and_marks_corrupted(client, sample, event):
    content = _pdf(b"tamper-marker")
    rec = _upload(client, event["id"], "证据.pdf", content).json()
    blob = att.blob_path(rec["sha256"])

    # 篡改实体内容 -> 下载 409，列表标为损坏（摘要不一致）
    with open(blob, "ab") as f:
        f.write(b"x")
    resp = client.get(f"/api/attachments/{rec['id']}/download")
    assert resp.status_code == 409
    assert "不一致" in resp.json()["detail"]
    att0 = _attachments(client, sample["id"])[0]
    assert att0["integrity"] == "mismatch"
    assert "损坏" in att0["integrity_text"]

    # 完整性刷新：复算后仍为损坏
    vf = client.post(f"/api/events/{event['id']}/attachments/verify")
    assert vf.status_code == 200
    assert vf.json()[0]["integrity"] == "mismatch"

    # 修复实体内容 -> 刷新恢复完整，下载恢复 200
    with open(blob, "wb") as f:
        f.write(content)
    single = client.post(f"/api/attachments/{rec['id']}/verify")
    assert single.status_code == 200
    assert single.json()["integrity"] == "ok"
    assert client.get(f"/api/attachments/{rec['id']}/download").status_code == 200


def test_download_detects_missing_blob(client, sample, event):
    content = _png(b"missing-marker")
    rec = _upload(client, event["id"], "照片.png", content, mime="image/png").json()
    os.remove(att.blob_path(rec["sha256"]))

    resp = client.get(f"/api/attachments/{rec['id']}/download")
    assert resp.status_code == 409
    assert "缺失" in resp.json()["detail"]
    assert _attachments(client, sample["id"])[0]["integrity"] == "missing"


# ---------- 事件删除保护与样本级联清理 ----------

def test_event_delete_blocked_until_attachments_removed(client, sample, event):
    rec = _upload(client, event["id"], "凭证.pdf", _pdf(b"guard")).json()

    resp = client.delete(f"/api/events/{event['id']}")
    assert resp.status_code == 409
    assert "附件" in resp.json()["detail"]

    assert client.delete(f"/api/attachments/{rec['id']}").status_code == 204
    assert client.delete(f"/api/events/{event['id']}").status_code == 204


def test_sample_delete_cleans_attachments_and_blobs(client, sample, event):
    rec = _upload(client, event["id"], "归档.pdf", _pdf(b"cleanup")).json()
    blob = att.blob_path(rec["sha256"])
    assert os.path.exists(blob)

    assert client.delete(f"/api/samples/{sample['id']}").status_code == 204
    assert not os.path.exists(blob)
    # 附件记录随事件一并清除
    assert client.get(f"/api/attachments/{rec['id']}/verify").status_code == 404


# ---------- 报告集成（只列元数据） ----------

def test_reports_list_attachment_metadata(client, sample, event):
    content = _pdf(b"report-marker")
    rec = _upload(client, event["id"], "报告附件.pdf", content, uploader="王五").json()

    md = client.get(f"/api/samples/{sample['id']}/report?format=markdown")
    assert md.status_code == 200
    assert "事件证据附件" in md.text
    assert "报告附件.pdf" in md.text
    assert "王五" in md.text
    assert rec["sha256"][:12] in md.text

    html = client.get(f"/api/samples/{sample['id']}/report?format=html")
    assert html.status_code == 200
    assert "事件证据附件" in html.text
    assert "报告附件.pdf" in html.text

    js = client.get(f"/api/samples/{sample['id']}/report?format=json").json()
    assert len(js["attachments"]) == 1
    meta = js["attachments"][0]
    assert meta["filename"] == "报告附件.pdf"
    assert meta["sha256"] == rec["sha256"]
    assert meta["uploaded_by"] == "王五"
    assert meta["integrity"] == "ok"
