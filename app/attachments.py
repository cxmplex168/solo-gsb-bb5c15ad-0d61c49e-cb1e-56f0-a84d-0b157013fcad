"""事件证据附件：内容寻址存储 + 完整性校验。

每个交接事件可上传 PDF / JPEG / PNG 证据文件（单文件不超过 10 MiB）。
服务端**流式落盘**并同步计算 SHA-256，实体文件按摘要做内容寻址
（``<附件目录>/<摘要前两位>/<完整摘要>``）：相同内容全库只存一份实体
（``attachment_blobs`` 一行 + 磁盘一个文件），每次上传仍生成独立的
附件记录（``attachments`` 一行），保留原文件名、大小、上传人、上传时间
与所属事件。

下载 / 校验前重新复算实体摘要：文件缺失（``missing``）或摘要不一致
（``mismatch``）时把记录标记为损坏并拒绝下载（409）；一致则标记 ``ok``。

删除附件只删除该条记录；仅当某个摘要不再被任何记录引用时，才删除实体行
与磁盘文件（引用计数垃圾回收）。有关联附件的事件禁止删除（由路由层校验）。
"""
from __future__ import annotations

import hashlib
import os
import tempfile
from datetime import datetime
from typing import Any, Optional
from sqlite3 import Connection

from .db import DB_PATH

# 单文件上限 10 MiB；流式读写分块 1 MiB
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
_CHUNK_SIZE = 1024 * 1024

# 附件实体根目录：默认与数据库文件同级的 attachments/（Docker 中为 /data/attachments）
ATTACHMENT_DIR = os.environ.get(
    "AUDIT_ATTACHMENT_DIR",
    os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), "attachments"),
)

# 完整性状态
INTEGRITY_OK = "ok"
INTEGRITY_MISSING = "missing"    # 实体文件缺失
INTEGRITY_MISMATCH = "mismatch"  # 实体摘要与记录不一致

INTEGRITY_TEXT = {
    INTEGRITY_OK: "完整",
    INTEGRITY_MISSING: "损坏（实体缺失）",
    INTEGRITY_MISMATCH: "损坏（摘要不一致）",
}

# 允许的格式：按文件头魔数嗅探（不信任客户端声明的扩展名 / Content-Type）
_MAGIC = (
    (b"%PDF-", "application/pdf", "PDF"),
    (b"\xff\xd8\xff", "image/jpeg", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "image/png", "PNG"),
)
_KIND_LABEL = {mime: label for _, mime, label in _MAGIC}


class AttachmentError(Exception):
    """附件业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 路径与基础工具 ----------

def ensure_dir() -> None:
    os.makedirs(ATTACHMENT_DIR, exist_ok=True)


def blob_path(sha256: str) -> str:
    """实体文件的内容寻址路径（按摘要前两位分片）。"""
    return os.path.join(ATTACHMENT_DIR, sha256[:2], sha256)


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _silent_remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK_SIZE), b""):
            h.update(chunk)
    return h.hexdigest()


def _sniff(head: bytes) -> Optional[tuple[str, str]]:
    """按魔数识别格式，返回 (MIME, 类型标签)；不支持的格式返回 None。"""
    for magic, mime, label in _MAGIC:
        if head.startswith(magic):
            return mime, label
    return None


def _safe_filename(name: Optional[str]) -> str:
    """保留原文件名用于展示，剥离路径成分与控制字符。"""
    name = (name or "").replace("\\", "/")
    name = os.path.basename(name).strip().strip(".")
    name = "".join(ch for ch in name if ch >= " " and ch != "\x7f")
    return (name or "attachment")[:128]


def fmt_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / 1024 / 1024:.2f} MB"


# ---------- 记录视图 ----------

def _record_dict(row: Any) -> dict[str, Any]:
    content_type = row["content_type"]
    integrity = row["integrity"]
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "filename": row["filename"],
        "content_type": content_type,
        "kind": _KIND_LABEL.get(content_type, content_type),
        "size": row["size"],
        "size_label": fmt_size(row["size"]),
        "sha256": row["sha256"],
        "uploaded_by": row["uploaded_by"],
        "uploaded_at": row["uploaded_at"],
        "integrity": integrity,
        "integrity_text": INTEGRITY_TEXT.get(integrity, integrity),
        "checked_at": row["checked_at"],
    }


def _fetch_row(conn: Connection, attachment_id: int) -> Any:
    row = conn.execute(
        "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    if row is None:
        raise AttachmentError("附件不存在", status_code=404)
    return row


def get_attachment(conn: Connection, attachment_id: int) -> dict[str, Any]:
    return _record_dict(_fetch_row(conn, attachment_id))


def list_event_attachments(conn: Connection, event_id: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM attachments WHERE event_id = ? ORDER BY id", (event_id,)
    ).fetchall()
    return [_record_dict(r) for r in rows]


def list_sample_attachments(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    """样本全部附件（含所属事件的录入序与经手人，供详情页与报告使用）。"""
    rows = conn.execute(
        "SELECT a.*, e.seq AS event_seq, e.custodian AS event_custodian "
        "FROM attachments a JOIN events e ON e.id = a.event_id "
        "WHERE e.sample_id = ? ORDER BY e.seq, a.id",
        (sample_id,),
    ).fetchall()
    result = []
    for r in rows:
        d = _record_dict(r)
        d["event_seq"] = r["event_seq"]
        d["event_custodian"] = r["event_custodian"]
        result.append(d)
    return result


def event_attachment_count(conn: Connection, event_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM attachments WHERE event_id = ?", (event_id,)
    ).fetchone()[0]


# ---------- 上传（流式落盘 + 内容寻址） ----------

async def store_upload(
    conn: Connection, event_id: int, upload: Any, uploader: str
) -> dict[str, Any]:
    """流式保存上传内容：边写临时文件边算 SHA-256，完成后按摘要内容寻址。

    ``upload`` 只需提供 ``async read(n)`` 与 ``filename``（FastAPI UploadFile）。
    相同内容只保留一份实体文件；本次上传仍生成独立附件记录。
    若已存在的实体文件损坏，用本次上传的健康内容修复。
    """
    ensure_dir()
    fd, tmp_path = tempfile.mkstemp(prefix=".incoming-", dir=ATTACHMENT_DIR)
    hasher = hashlib.sha256()
    size = 0
    detected: Optional[tuple[str, str]] = None
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = await upload.read(_CHUNK_SIZE)
                if not chunk:
                    break
                if detected is None:
                    detected = _sniff(chunk)
                    if detected is None:
                        raise AttachmentError(
                            "仅支持 PDF、JPEG、PNG 格式的证据文件", status_code=415
                        )
                size += len(chunk)
                if size > MAX_ATTACHMENT_BYTES:
                    raise AttachmentError(
                        "文件超过 10 MiB 大小限制", status_code=413
                    )
                hasher.update(chunk)
                out.write(chunk)
    except BaseException:
        _silent_remove(tmp_path)
        raise
    if size == 0:
        _silent_remove(tmp_path)
        raise AttachmentError("不能上传空文件", status_code=400)

    content_type, _ = detected
    sha256 = hasher.hexdigest()
    final_path = blob_path(sha256)
    if os.path.exists(final_path):
        if _hash_file(final_path) == sha256:
            _silent_remove(tmp_path)  # 相同内容只存一份实体
        else:
            os.replace(tmp_path, final_path)  # 实体已损坏，用新内容修复
    else:
        os.makedirs(os.path.dirname(final_path), exist_ok=True)
        os.replace(tmp_path, final_path)

    now = _now()
    conn.execute(
        "INSERT OR IGNORE INTO attachment_blobs (sha256, size, created_at) "
        "VALUES (?, ?, ?)",
        (sha256, size, now),
    )
    cur = conn.execute(
        "INSERT INTO attachments (event_id, filename, content_type, size, sha256, "
        "uploaded_by, uploaded_at, integrity, checked_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            event_id,
            _safe_filename(getattr(upload, "filename", None)),
            content_type,
            size,
            sha256,
            uploader,
            now,
            INTEGRITY_OK,
            now,
        ),
    )
    return get_attachment(conn, cur.lastrowid)


# ---------- 完整性复算 ----------

def check_blob(sha256: str) -> str:
    """复算实体摘要，返回 ok / missing / mismatch。"""
    path = blob_path(sha256)
    if not os.path.exists(path):
        return INTEGRITY_MISSING
    return INTEGRITY_OK if _hash_file(path) == sha256 else INTEGRITY_MISMATCH


def _refresh_row(conn: Connection, row: Any) -> dict[str, Any]:
    status = check_blob(row["sha256"])
    conn.execute(
        "UPDATE attachments SET integrity = ?, checked_at = ? WHERE id = ?",
        (status, _now(), row["id"]),
    )
    return get_attachment(conn, row["id"])


def verify_attachment(conn: Connection, attachment_id: int) -> dict[str, Any]:
    """完整性刷新（单条）：复算摘要并更新记录状态。"""
    return _refresh_row(conn, _fetch_row(conn, attachment_id))


def verify_event_attachments(conn: Connection, event_id: int) -> list[dict[str, Any]]:
    """完整性刷新（事件全部附件）：复算摘要并更新记录状态。"""
    rows = conn.execute(
        "SELECT * FROM attachments WHERE event_id = ? ORDER BY id", (event_id,)
    ).fetchall()
    return [_refresh_row(conn, r) for r in rows]


def prepare_download(conn: Connection, attachment_id: int) -> tuple[str, dict[str, Any]]:
    """下载前复算摘要；缺失或不一致时标记损坏并抛 409（调用方负责提交标记）。"""
    row = _fetch_row(conn, attachment_id)
    record = _refresh_row(conn, row)
    if record["integrity"] == INTEGRITY_MISSING:
        raise AttachmentError("附件实体文件缺失，已标记为损坏", status_code=409)
    if record["integrity"] == INTEGRITY_MISMATCH:
        raise AttachmentError("附件实体摘要与记录不一致，已标记为损坏", status_code=409)
    return blob_path(row["sha256"]), record


# ---------- 删除与实体回收 ----------

def _gc_blob(conn: Connection, sha256: str) -> None:
    """最后一个引用移除后才清理实体（记录行 + 磁盘文件）。"""
    refs = conn.execute(
        "SELECT COUNT(*) FROM attachments WHERE sha256 = ?", (sha256,)
    ).fetchone()[0]
    if refs:
        return
    conn.execute("DELETE FROM attachment_blobs WHERE sha256 = ?", (sha256,))
    path = blob_path(sha256)
    _silent_remove(path)
    try:
        os.rmdir(os.path.dirname(path))  # 分片目录空则一并清理
    except OSError:
        pass


def delete_attachment(conn: Connection, attachment_id: int) -> None:
    """删除附件记录（仅解除该记录）；实体按引用计数回收。"""
    row = _fetch_row(conn, attachment_id)
    conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
    _gc_blob(conn, row["sha256"])


def delete_attachments_for_events(conn: Connection, event_ids: list[int]) -> None:
    """样本删除时级联清理：删除这些事件的全部附件记录并回收无引用实体。"""
    if not event_ids:
        return
    marks = ",".join("?" for _ in event_ids)
    shas = [
        r["sha256"]
        for r in conn.execute(
            f"SELECT DISTINCT sha256 FROM attachments WHERE event_id IN ({marks})",
            event_ids,
        ).fetchall()
    ]
    conn.execute(
        f"DELETE FROM attachments WHERE event_id IN ({marks})", event_ids
    )
    for sha in shas:
        _gc_blob(conn, sha)
