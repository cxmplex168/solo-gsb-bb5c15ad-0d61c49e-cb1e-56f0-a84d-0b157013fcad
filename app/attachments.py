"""交接事件证据附件：内容寻址（SHA-256）存储 + 每次上传独立记录。

存储分两层：

* ``attachment_blobs`` / 附件目录中的实体文件：按文件内容的 SHA-256 摘要
  内容寻址，相同内容（即使文件名不同）只落盘一份；
* ``attachments`` / 附件记录：每次上传都保留独立的一行，记录原文件名、
  大小、上传人、上传时间与所属事件，引用 blob 摘要。

删除附件只解除该条记录；仅当最后一个引用移除（引用计数归零）时才清理
实体文件。下载前必须现场复算摘要：实体缺失或摘要不一致返回 409 冲突，
并在列表中标记为「损坏」。
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, BinaryIO, Optional
from sqlite3 import Connection

from fastapi import UploadFile

# 单文件上限：10 MiB
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

# 允许的证据类型：PDF / JPEG / PNG
MEDIA_TYPES: dict[bytes, tuple[str, str]] = {
    b"%PDF": ("application/pdf", "pdf"),
    b"\xff\xd8\xff": ("image/jpeg", "jpeg"),
    b"\x89PNG\r\n\x1a\n": ("image/png", "png"),
}
ALLOWED_MEDIA = {"application/pdf", "image/jpeg", "image/png"}
ALLOWED_EXTENSIONS = {"pdf", "jpg", "jpeg", "png"}

# 附件记录完整性状态
STATUS_OK = "ok"
STATUS_CORRUPT = "corrupt"

# 损坏原因
REASON_MISSING = "missing"
REASON_MISMATCH = "digest_mismatch"
REASON_TEXT = {
    REASON_MISSING: "实体文件缺失",
    REASON_MISMATCH: "摘要不一致（内容可能已损坏或被篡改）",
}

# 序列化「删除引用 -> 引用计数归零 -> 清理实体」与「上传去重 -> 引用」，
# 避免并发删除把另一次上传刚引用的实体删掉。
_blob_lock = threading.Lock()


class AttachmentError(Exception):
    """业务校验失败，由路由层转换为 HTTPException。"""

    def __init__(self, message: str, status_code: int = 409):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


# ---------- 存储目录 ----------

def attachment_dir() -> Path:
    """附件实体根目录。

    默认放在数据库文件旁的 ``attachments`` 目录；可用环境变量
    ``ATTACHMENT_DIR`` 覆盖（容器内为 /data/attachments）。
    """
    env = os.environ.get("ATTACHMENT_DIR")
    if env:
        path = Path(env)
    else:
        from .db import DB_PATH

        path = Path(DB_PATH).resolve().parent / "attachments"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _blob_path(digest: str) -> Path:
    # 两级分片（ab/cd/<64hex>），避免单目录文件过多
    return attachment_dir() / digest[:2] / digest[2:4] / digest


def _prune_parents(path: Path) -> None:
    """实体删除后向上清理空的分片目录（根目录保留）。"""
    root = attachment_dir()
    parent = path.parent
    while parent != root:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent


# ---------- 工具 ----------

def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def detect_media(head: bytes) -> Optional[str]:
    """按文件头魔数识别真实类型，识别不出返回 None。"""
    for magic, (media, _ext) in MEDIA_TYPES.items():
        if head.startswith(magic):
            return media
    return None


def validate_filename(name: str) -> str:
    name = (name or "").strip()
    if not name:
        raise AttachmentError("文件名不能为空", status_code=422)
    if len(name) > 255:
        raise AttachmentError("文件名过长（最多 255 字符）", status_code=422)
    if "/" in name or "\\" in name or name in (".", "..") or "\x00" in name:
        raise AttachmentError("文件名包含非法字符", status_code=422)
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise AttachmentError("仅支持 PDF、JPEG、PNG 附件（.pdf/.jpg/.jpeg/.png）",
                              status_code=422)
    return name


def human_size(num: int) -> str:
    value = float(num)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            if unit == "B":
                return f"{int(value)} B"
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _stream_to_temp(src: BinaryIO, root: Path) -> tuple[Path, hashlib._Hash, int, bytes]:
    """流式读取上传内容到临时文件，同时计算 SHA-256；超过 10 MiB 立即拒绝。

    返回（临时文件路径, 摘要器, 字节数, 首个分块）。
    """
    tmp = tempfile.NamedTemporaryFile(delete=False, dir=root, prefix=".upload-", suffix=".tmp")
    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            if size == 0:
                head = chunk[:8]
            size += len(chunk)
            if size > MAX_ATTACHMENT_BYTES:
                raise AttachmentError(
                    f"附件超过大小上限（{human_size(MAX_ATTACHMENT_BYTES)}）",
                    status_code=413,
                )
            digest.update(chunk)
            tmp.write(chunk)
        if size == 0:
            raise AttachmentError("附件内容为空", status_code=422)
        tmp.flush()
        os.fsync(tmp.fileno())
        return Path(tmp.name), digest, size, head
    except Exception:
        tmp.close()
        Path(tmp.name).unlink(missing_ok=True)
        raise
    finally:
        # 成功路径下由调用方负责关闭/删除临时文件
        if not tmp.closed:
            tmp.close()


# ---------- 上传（流式落盘 + 内容寻址） ----------

def save_attachment(
    conn: Connection,
    event_id: int,
    upload: UploadFile,
    uploaded_by: str,
    *,
    time: Optional[str] = None,
) -> dict[str, Any]:
    """流式保存上传附件：校验类型/大小，按 SHA-256 内容寻址，写入附件记录。

    相同内容只存一份 blob，但每次上传都保留独立附件记录。
    """
    filename = validate_filename(upload.filename or "")
    uploaded_by = (uploaded_by or "").strip()
    if not uploaded_by:
        raise AttachmentError("上传人不能为空", status_code=422)
    if len(uploaded_by) > 64:
        raise AttachmentError("上传人姓名过长（最多 64 字符）", status_code=422)

    root = attachment_dir()
    tmp_path, hasher, size, head = _stream_to_temp(upload.file, root)

    declared = (upload.content_type or "").split(";", 1)[0].strip().lower()
    actual = detect_media(head)
    if actual is None:
        tmp_path.unlink(missing_ok=True)
        raise AttachmentError(
            "无法识别的文件类型：仅支持 PDF、JPEG、PNG（按文件内容校验）",
            status_code=415,
        )
    if declared and declared not in ALLOWED_MEDIA:
        tmp_path.unlink(missing_ok=True)
        raise AttachmentError(f"不支持的文件类型：{declared}（仅支持 PDF、JPEG、PNG）",
                              status_code=415)
    if declared and declared != actual:
        tmp_path.unlink(missing_ok=True)
        raise AttachmentError(
            f"文件内容（{actual}）与声明类型（{declared}）不一致",
            status_code=415,
        )
    ext_expected = {
        "pdf": "application/pdf",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
    }
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext_expected.get(ext) != actual:
        tmp_path.unlink(missing_ok=True)
        raise AttachmentError("文件扩展名与实际内容不一致", status_code=415)

    digest = hasher.hexdigest()
    uploaded_at = time or now_text()

    try:
        with _blob_lock:
            conn.execute("BEGIN IMMEDIATE")
            try:
                target = _blob_path(digest)
                if not target.exists():
                    # 新实体（或实体丢失但 blob 行仍在的修复路径）：
                    # 临时文件原子移入分片目录，blob 行用 INSERT OR IGNORE 幂等补齐
                    target.parent.mkdir(parents=True, exist_ok=True)
                    shutil.move(str(tmp_path), str(target))
                    tmp_path = None
                    conn.execute(
                        "INSERT OR IGNORE INTO attachment_blobs (digest, size, media_type, created_at) "
                        "VALUES (?, ?, ?, ?)",
                        (digest, size, actual, uploaded_at),
                    )
                cur = conn.execute(
                    # 事件存在性由数据库外键兜底；路由层会先做 404 检查
                    "INSERT INTO attachments "
                    "(event_id, blob_digest, filename, size, media_type, uploaded_by, "
                    " uploaded_at, status, corruption_reason, last_verified_at, created_at) "
                    "SELECT ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ? FROM events WHERE id = ?",
                    (event_id, digest, filename, size, actual, uploaded_by,
                     uploaded_at, STATUS_OK, uploaded_at, uploaded_at, event_id),
                )
                if cur.rowcount == 0:
                    raise AttachmentError("交接事件不存在", status_code=404)
                conn.commit()
            except Exception:
                conn.rollback()
                raise
    finally:
        # 任何失败路径（含事件不存在）都要清理临时文件
        if tmp_path is not None:
            Path(tmp_path).unlink(missing_ok=True)

    attachment_id = cur.lastrowid
    return get_attachment(conn, attachment_id) or {}


# ---------- 完整性校验 ----------

def _mark_status(
    conn: Connection, attachment_id: int, ok: bool, reason: Optional[str], when: str
) -> None:
    conn.execute(
        "UPDATE attachments SET status = ?, corruption_reason = ?, last_verified_at = ? "
        "WHERE id = ?",
        (STATUS_OK if ok else STATUS_CORRUPT, None if ok else reason, when, attachment_id),
    )


def verify_blob(digest: str, expected_size: int) -> tuple[bool, Optional[str]]:
    """现场复算实体文件 SHA-256：(是否一致, 损坏原因)。"""
    path = _blob_path(digest)
    if not path.exists():
        return False, REASON_MISSING
    hasher = hashlib.sha256()
    total = 0
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            hasher.update(chunk)
    if total != expected_size or hasher.hexdigest() != digest:
        return False, REASON_MISMATCH
    return True, None


def verify_and_prepare_download(conn: Connection, attachment_id: int) -> dict[str, Any]:
    """下载前校验：返回附件视图与实体路径；缺失 / 不一致标记损坏并抛 409。"""
    row = conn.execute(
        "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    if row is None:
        raise AttachmentError("附件不存在", status_code=404)
    ok, reason = verify_blob(row["blob_digest"], row["size"])
    when = now_text()
    with _blob_lock:
        conn.execute("BEGIN IMMEDIATE")
        try:
            _mark_status(conn, attachment_id, ok, reason, when)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    if not ok:
        raise AttachmentError(
            f"附件完整性校验失败：{REASON_TEXT[reason]}，已在列表中标记为损坏",
            status_code=409,
        )
    result = dict(get_attachment(conn, attachment_id) or {})
    result["path"] = str(_blob_path(row["blob_digest"]))
    return result


def refresh_attachment(conn: Connection, attachment_id: int) -> dict[str, Any]:
    """完整性刷新：复算单个附件摘要并更新状态。"""
    row = conn.execute(
        "SELECT id, blob_digest, size FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    if row is None:
        raise AttachmentError("附件不存在", status_code=404)
    ok, reason = verify_blob(row["blob_digest"], row["size"])
    _mark_status(conn, attachment_id, ok, reason, now_text())
    conn.commit()
    return get_attachment(conn, attachment_id) or {}


def refresh_event_attachments(conn: Connection, event_id: int) -> list[dict[str, Any]]:
    """刷新某事件下全部附件的完整性状态。"""
    rows = conn.execute(
        "SELECT id FROM attachments WHERE event_id = ? ORDER BY id", (event_id,)
    ).fetchall()
    for r in rows:
        refresh_attachment(conn, r["id"])
    return list_event_attachments(conn, event_id)


# ---------- 查询 ----------

def _attachment_dict(row: Any) -> dict[str, Any]:
    reason = row["corruption_reason"]
    return {
        "id": row["id"],
        "event_id": row["event_id"],
        "filename": row["filename"],
        "size": row["size"],
        "size_text": human_size(row["size"]),
        "media_type": row["media_type"],
        "uploaded_by": row["uploaded_by"],
        "uploaded_at": row["uploaded_at"],
        "digest": row["blob_digest"],
        "status": row["status"],
        "corruption_reason": reason,
        "corruption_reason_text": REASON_TEXT.get(reason) if reason else None,
        "last_verified_at": row["last_verified_at"],
    }


def get_attachment(conn: Connection, attachment_id: int) -> Optional[dict[str, Any]]:
    row = conn.execute(
        "SELECT * FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    return _attachment_dict(row) if row else None


def _scan_existence(conn: Connection, event_id: Optional[int] = None) -> None:
    """轻量检查：实体缺失的附件在列表中直接标为损坏（不做全量复算）。"""
    sql = "SELECT id, blob_digest FROM attachments WHERE status = ?"
    params: list[Any] = [STATUS_OK]
    if event_id is not None:
        sql += " AND event_id = ?"
        params.append(event_id)
    when = now_text()
    changed = False
    for r in conn.execute(sql, params).fetchall():
        if not _blob_path(r["blob_digest"]).exists():
            conn.execute(
                "UPDATE attachments SET status = ?, corruption_reason = ?, "
                "last_verified_at = ? WHERE id = ?",
                (STATUS_CORRUPT, REASON_MISSING, when, r["id"]),
            )
            changed = True
    if changed:
        conn.commit()


def list_event_attachments(conn: Connection, event_id: int) -> list[dict[str, Any]]:
    _scan_existence(conn, event_id)
    rows = conn.execute(
        "SELECT * FROM attachments WHERE event_id = ? ORDER BY id", (event_id,)
    ).fetchall()
    return [_attachment_dict(r) for r in rows]


def list_sample_attachments(conn: Connection, sample_id: int) -> list[dict[str, Any]]:
    """样本详情用：返回该样本全部事件的附件（轻量缺失检查）。"""
    _scan_existence(conn)
    rows = conn.execute(
        "SELECT a.* FROM attachments a JOIN events e ON e.id = a.event_id "
        "WHERE e.sample_id = ? ORDER BY a.id",
        (sample_id,),
    ).fetchall()
    return [_attachment_dict(r) for r in rows]


# ---------- 删除（引用计数，最后一个引用移除后才清理实体） ----------

def delete_attachment(conn: Connection, attachment_id: int) -> dict[str, Any]:
    """删除附件记录；引用计数归零后才删除内容寻址实体文件。"""
    row = conn.execute(
        "SELECT blob_digest FROM attachments WHERE id = ?", (attachment_id,)
    ).fetchone()
    if row is None:
        raise AttachmentError("附件不存在", status_code=404)
    digest = row["blob_digest"]
    with _blob_lock:
        conn.execute("BEGIN IMMEDIATE")
        try:
            conn.execute("DELETE FROM attachments WHERE id = ?", (attachment_id,))
            refs = conn.execute(
                "SELECT COUNT(*) FROM attachments WHERE blob_digest = ?", (digest,)
            ).fetchone()[0]
            blob_removed = False
            if refs == 0:
                conn.execute("DELETE FROM attachment_blobs WHERE digest = ?", (digest,))
                path = _blob_path(digest)
                if path.exists():
                    path.unlink()
                _prune_parents(path)
                blob_removed = True
            conn.commit()
        except Exception:
            conn.rollback()
            raise
    return {"deleted": True, "attachment_id": attachment_id, "blob_removed": blob_removed}


# ---------- 事件 / 样本删除保护 ----------

def attachment_count_for_event(conn: Connection, event_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM attachments WHERE event_id = ?", (event_id,)
    ).fetchone()[0]


def attachment_count_for_sample(conn: Connection, sample_id: int) -> int:
    return conn.execute(
        "SELECT COUNT(*) FROM attachments WHERE event_id IN "
        "(SELECT id FROM events WHERE sample_id = ?)",
        (sample_id,),
    ).fetchone()[0]
