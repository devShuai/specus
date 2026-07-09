export type MediaKind = "image" | "video" | "audio" | "pdf" | "text" | "document" | "archive" | "file";

const IMAGE_EXTENSIONS = new Set(["avif", "bmp", "gif", "heic", "heif", "jpeg", "jpg", "png", "svg", "webp"]);
const VIDEO_EXTENSIONS = new Set(["3gp", "avi", "m4v", "mkv", "mov", "mp4", "mpeg", "mpg", "ogv", "webm"]);
const AUDIO_EXTENSIONS = new Set(["aac", "flac", "m4a", "mp3", "oga", "ogg", "opus", "wav", "weba"]);
const TEXT_EXTENSIONS = new Set([
  "c", "conf", "config", "cpp", "cs", "css", "csv", "env", "go", "h", "html", "ini", "java", "js", "json",
  "jsx", "log", "md", "mjs", "properties", "py", "rb", "rs", "sh", "sql", "svg", "toml", "ts", "tsx", "txt",
  "xml", "yaml", "yml",
]);
const DOCUMENT_EXTENSIONS = new Set(["doc", "docx", "key", "numbers", "odp", "ods", "odt", "pages", "ppt", "pptx", "rtf", "xls", "xlsx"]);
const ARCHIVE_EXTENSIONS = new Set(["7z", "bz2", "gz", "rar", "tar", "tgz", "xz", "zip"]);

export function effectiveMimeType(fileName: string, mimeType?: string | null) {
  const normalized = mimeType?.trim().toLowerCase();
  if (normalized && normalized !== "application/octet-stream") {
    return normalized;
  }
  const ext = fileExtension(fileName);
  switch (ext) {
    case "avif":
      return "image/avif";
    case "bmp":
      return "image/bmp";
    case "gif":
      return "image/gif";
    case "heic":
      return "image/heic";
    case "heif":
      return "image/heif";
    case "jpg":
    case "jpeg":
      return "image/jpeg";
    case "png":
      return "image/png";
    case "svg":
      return "image/svg+xml";
    case "webp":
      return "image/webp";
    case "3gp":
      return "video/3gpp";
    case "avi":
      return "video/x-msvideo";
    case "m4v":
      return "video/x-m4v";
    case "mkv":
      return "video/x-matroska";
    case "mov":
      return "video/quicktime";
    case "mp4":
      return "video/mp4";
    case "mpeg":
    case "mpg":
      return "video/mpeg";
    case "ogv":
      return "video/ogg";
    case "webm":
      return "video/webm";
    case "aac":
      return "audio/aac";
    case "flac":
      return "audio/flac";
    case "m4a":
      return "audio/mp4";
    case "mp3":
      return "audio/mpeg";
    case "oga":
    case "ogg":
      return "audio/ogg";
    case "opus":
      return "audio/opus";
    case "wav":
      return "audio/wav";
    case "weba":
      return "audio/webm";
    case "pdf":
      return "application/pdf";
    case "csv":
      return "text/csv";
    case "html":
      return "text/html";
    case "json":
      return "application/json";
    case "log":
    case "txt":
      return "text/plain";
    case "md":
      return "text/markdown";
    case "xml":
      return "application/xml";
    case "yaml":
    case "yml":
      return "application/yaml";
    case "doc":
      return "application/msword";
    case "docx":
      return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    case "ppt":
      return "application/vnd.ms-powerpoint";
    case "pptx":
      return "application/vnd.openxmlformats-officedocument.presentationml.presentation";
    case "xls":
      return "application/vnd.ms-excel";
    case "xlsx":
      return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";
    case "zip":
      return "application/zip";
    default:
      if (TEXT_EXTENSIONS.has(ext)) {
        return "text/plain";
      }
      return normalized || "application/octet-stream";
  }
}

export function mediaKind(fileName: string, mimeType?: string | null): MediaKind {
  const type = effectiveMimeType(fileName, mimeType);
  if (type.startsWith("image/")) {
    return "image";
  }
  if (type.startsWith("video/")) {
    return "video";
  }
  if (type.startsWith("audio/")) {
    return "audio";
  }
  if (type === "application/pdf") {
    return "pdf";
  }
  if (type.startsWith("text/")
    || type === "application/json"
    || type === "application/xml"
    || type === "application/yaml"
    || type.endsWith("+json")
    || type.endsWith("+xml")) {
    return "text";
  }
  const ext = fileExtension(fileName);
  if (IMAGE_EXTENSIONS.has(ext)) {
    return "image";
  }
  if (VIDEO_EXTENSIONS.has(ext)) {
    return "video";
  }
  if (AUDIO_EXTENSIONS.has(ext)) {
    return "audio";
  }
  if (ext === "pdf") {
    return "pdf";
  }
  if (TEXT_EXTENSIONS.has(ext)) {
    return "text";
  }
  if (DOCUMENT_EXTENSIONS.has(ext)) {
    return "document";
  }
  if (ARCHIVE_EXTENSIONS.has(ext)) {
    return "archive";
  }
  return "file";
}

export function previewKindLabel(kind: MediaKind) {
  switch (kind) {
    case "image":
      return "IMAGE";
    case "video":
      return "VIDEO";
    case "audio":
      return "AUDIO";
    case "pdf":
      return "PDF";
    case "text":
      return "TEXT";
    case "document":
      return "DOC";
    case "archive":
      return "ZIP";
    default:
      return "FILE";
  }
}

export function shortMimeLabel(mimeType: string) {
  const normalized = mimeType.replace(/^application\//, "").replace(/^text\//, "");
  return normalized.length > 24 ? `${normalized.slice(0, 21)}...` : normalized;
}

function fileExtension(fileName: string) {
  const cleanName = fileName.trim().split(/[\\/]/).pop() || "";
  const dot = cleanName.lastIndexOf(".");
  if (dot < 0 || dot === cleanName.length - 1) {
    return "";
  }
  return cleanName.slice(dot + 1).toLowerCase();
}


