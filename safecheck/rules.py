"""Explainable red-flag rules for Vietnamese (and some English) scam messages.

The ML model gives a probability; these rules explain *why* a message looks risky,
so every check teaches the user something.
"""
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlparse


def normalize(text: str) -> str:
    """Lowercase and strip Vietnamese accents so 'Tài khoản' and 'Tai khoan' match."""
    text = text.lower().replace("đ", "d")
    text = unicodedata.normalize("NFD", text)
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Mn")
    return re.sub(r"\s+", " ", text).strip()


@dataclass
class Flag:
    id: str
    weight: int          # how much this flag adds to the risk score (0-100 scale)
    title_vi: str        # short label shown to the user
    advice_vi: str       # one-line explanation / what to do


# Each rule: (Flag, list of regex patterns matched against normalized text)
KEYWORD_RULES = [
    (Flag("otp", 35, "Yêu cầu mã OTP, mật khẩu hoặc thông tin thẻ",
          "Ngân hàng và nhà mạng không bao giờ hỏi OTP, mật khẩu hay mã CVV. Không cung cấp cho bất kỳ ai."),
     [r"\b(doc|gui|cung cap|nhap|dua)\b.{0,25}\b(ma )?(otp|ma xac (nhan|thuc))",
      r"\b(doc|gui|cung cap|nhap|dua|xac nhan bang)\b.{0,30}\b(mat khau|password|cvv|so the|ten dang nhap)\b",
      r"\bma cvv\b", r"\bgui (qua day )?ma the\b", r"\bsend .{0,20}(bank details|password)\b"]),
    (Flag("authority", 30, "Mạo danh công an, cơ quan nhà nước",
          "Công an, Viện kiểm sát không làm việc qua điện thoại hay tin nhắn và không yêu cầu chuyển tiền."),
     [r"\b(cong an|can bo|vien kiem sat|co quan dieu tra|toa an|lenh (trieu tap|bat)|cuc thue|bao hiem xa hoi|bhxh)\b",
      r"\b(rua tien|duong day ma tuy|tai khoan tam giu)\b"]),
    (Flag("account_threat", 20, "Đe dọa khóa tài khoản / dịch vụ",
          "Tin giả thường dọa khóa tài khoản để bạn hoảng. Hãy tự mở ứng dụng chính thức để kiểm tra."),
     [r"\b(bi|se bi) (tam )?(khoa|vo hieu hoa|xoa|dong|cat)\b",
      r"\b(khoa|dong) (vinh vien|2 chieu|hai chieu)\b",
      r"\b(on hold|limited|suspended|disabled)\b"]),
    (Flag("urgency", 15, "Tạo áp lực thời gian, khẩn cấp",
          "Kẻ lừa đảo muốn bạn hành động trước khi kịp suy nghĩ. Hãy dừng lại và hỏi người tin cậy."),
     [r"\b(gap|khan|ngay lap tuc|truoc \d+ ?h|trong \d+ ?(h|gio|phut|tieng)|het han|co hoi cuoi|chi con \d+)\b",
      r"\b(urgent|immediately|within \d+ hours?)\b", r"!{2,}"]),
    (Flag("money_request", 25, "Yêu cầu chuyển tiền, đặt cọc hoặc nộp phí",
          "Không chuyển tiền hay 'phí mở khóa', 'phí hồ sơ' cho người lạ. Gọi lại số quen thuộc để xác minh."),
     [r"\bchuyen (gap|ngay|truoc|tien|giup|lai|khoan)\b.{0,40}\b(vao|tai khoan|so tai khoan|so nay|so khac)\b",
      r"\b(nop|dong|chuyen|thanh toan) (phi|tien coc|dat coc|coc)\b",
      r"\bdat coc\b", r"\bphi (van chuyen|ho so|xu ly|bao hiem|mo khoa|giu cho|dao tao)\b",
      r"\bmo khoa (khoan vay|don hang)\b", r"\bnap tien\b",
      r"\b(processing|training) fee\b", r"\bmua (giup|ho) .{0,20}the cao\b"]),
    (Flag("prize", 20, "Trúng thưởng, quà tặng bất ngờ",
          "Bạn không tham gia chương trình nào thì không thể trúng thưởng. Quà miễn phí mà phải nộp phí là lừa đảo."),
     [r"\b(trung thuong|trung giai|khach hang may man|qua tang|tri an|minigame|nhan thuong|voucher)\b",
      r"\bnhan (duoc )?(qua|phan qua|tien thuong)\b",
      r"\b(you have won|claim your prize|gift package)\b"]),
    (Flag("easy_money", 25, "Việc nhẹ lương cao, lợi nhuận phi thực tế",
          "Không có công việc hay khoản đầu tư nào hứa thu nhập cao, 'cam kết không lỗ'. Đây là dấu hiệu lừa đảo phổ biến."),
     [r"\bviec nhe luong cao\b", r"\b(lam nhiem vu|nhan nhiem vu|hoa hong)\b",
      r"\bloi nhuan \d+ ?%", r"\bcam ket (khong lo|loi nhuan)\b", r"\b(tien ao|tin hieu|nhom kin|vip)\b",
      r"\bkhong can (the chap|kinh nghiem)\b", r"\bgiai ngan\b", r"\$\d+ ?/ ?day\b"]),
    (Flag("secrecy", 20, "Yêu cầu giữ bí mật, không báo người thân",
          "Kẻ lừa đảo cô lập nạn nhân. Luôn kể với gia đình hoặc bạn bè trước khi làm theo."),
     [r"\bkhong (duoc )?(bao|noi|ke) (cho )?(nguoi than|ai|gia dinh)\b", r"\bdung goi lai\b",
      r"\bbi mat\b"]),
    (Flag("impersonate_relative", 20, "Giả làm người thân, bạn bè đổi số / mất máy",
          "Gọi video hoặc gọi vào số cũ để xác minh trước khi chuyển tiền cho 'người quen'."),
     [r"\b(mat dien thoai|so moi cua con|tai khoan bi khoa|dang ket|cap cuu|tai nan)\b",
      r"\b(me|bo|chi|anh|ban) oi\b.{0,60}\bchuyen\b"]),
    (Flag("sextortion", 45, "Đe dọa phát tán ảnh, video riêng tư",
          "Đây là tống tiền. Không chuyển tiền, lưu bằng chứng, chặn và báo cáo; tìm sự hỗ trợ từ người tin cậy."),
     [r"\b(anh|video) (nhay cam|rieng tu)\b.{0,80}\b(gui|phat tan|dang)\b",
      r"\b(phat tan|gui cho toan bo)\b", r"\bgui anh rieng tu\b"]),
    (Flag("remote_app", 30, "Yêu cầu cài ứng dụng lạ hoặc điều khiển máy",
          "Chỉ cài ứng dụng từ App Store / Google Play. Ứng dụng lạ có thể chiếm quyền điện thoại và rút tiền."),
     [r"\bcai (dat )?(ung dung|app)\b.{0,30}\b(link|duong link|theo)\b", r"\bdieu khien may\b",
      r"\btai ung dung\b.{0,30}\btai day\b"]),
    (Flag("id_docs", 25, "Yêu cầu ảnh CCCD, giấy tờ tùy thân",
          "Không gửi ảnh CCCD cho người lạ; chúng có thể bị dùng để vay tiền hoặc mở tài khoản giả mạo."),
     [r"\b(anh )?(2|hai) mat (cccd|can cuoc)\b", r"\bgui (anh )?(cccd|can cuoc)\b"]),
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "cutt.ly", "shorturl.at", "rb.gy", "is.gd"}
RISKY_TLDS = {"top", "xyz", "click", "online", "shop", "site", "info", "vip", "icu", "buzz", "live", "cc", "tk"}
BRANDS = ["vietcombank", "vcb", "techcombank", "tcb", "bidv", "agribank", "vietinbank", "mbbank", "acb", "tpbank",
          "vpbank", "sacombank", "hdbank", "vib", "shb", "seabank", "momo", "zalo", "facebook", "fb", "meta", "shopee", "lazada", "tiki",
          "viettel", "mobifone", "vinaphone", "vnpost", "evn", "vneid", "paypal", "netflix", "garena"]
OFFICIAL_DOMAINS = {"vietcombank.com.vn", "techcombank.com", "bidv.com.vn", "momo.vn", "zalo.me",
                    "facebook.com", "shopee.vn", "viettel.vn", "vnpost.vn", "evn.com.vn", "paypal.com",
                    "netflix.com", "google.com", "youtube.com", "chinhphu.vn"}
# any address under these is run by the government or a school
OFFICIAL_SUFFIXES = (".gov.vn", ".edu.vn")

URL_RE = re.compile(r"(https?://[^\s,]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s,]*)?)", re.IGNORECASE)


def _host(url: str) -> str:
    """Hostname of a URL or bare domain; '' if it can't be parsed (e.g. stray brackets)."""
    try:
        return (urlparse(url if "://" in url else "http://" + url).hostname or "").lower()
    except ValueError:
        return ""


def extract_urls(text: str) -> list[str]:
    urls = []
    for m in URL_RE.findall(text):
        m = m.rstrip(".)]")
        host = _host(m)
        # skip things like "5.000" or "29a-123.45" that aren't really domains
        if "." in host and re.search(r"[a-z]", host.split(".")[-1]):
            urls.append(m)
    return urls


def is_official(url: str) -> bool:
    host = _host(url).removeprefix("www.")
    return (host in OFFICIAL_DOMAINS or any(host.endswith("." + d) for d in OFFICIAL_DOMAINS)
            or host.endswith(OFFICIAL_SUFFIXES))


def check_url(url: str) -> list[Flag]:
    flags = []
    host = _host(url).removeprefix("www.")
    if is_official(url):
        return flags
    if host in SHORTENERS:
        flags.append(Flag("short_link", 20, f"Link rút gọn ({host})",
                          "Link rút gọn che giấu trang đích thật. Đừng bấm nếu không rõ người gửi."))
    tld = host.rsplit(".", 1)[-1]
    if tld in RISKY_TLDS:
        flags.append(Flag("risky_tld", 20, f"Tên miền đuôi .{tld} thường bị dùng để lừa đảo",
                          "Trang chính thức của ngân hàng, cơ quan ở Việt Nam thường dùng đuôi .vn hoặc .com.vn."))
    # Only a weak signal: HTTPS does NOT mean safe (most phishing sites have a padlock too),
    # but a page served over plain http:// is a bad place to type passwords or card details.
    if url.lower().startswith("http://"):
        flags.append(Flag("no_https", 10, "Link dùng http:// (không mã hóa)",
                          "Không nhập mật khẩu, OTP hay số thẻ trên trang http://. Lưu ý: có ổ khóa https:// "
                          "cũng KHÔNG có nghĩa là trang an toàn; hãy kiểm tra kỹ tên miền."))
    brand = next((b for b in BRANDS if re.search(rf"(^|[.-]){b}([.-]|$)", host)), None)
    if brand:
        flags.append(Flag("brand_lookalike", 35, f"Tên miền giả mạo thương hiệu '{brand}' ({host})",
                          "Tên thương hiệu ghép thêm chữ như '-xacminh', '-hoantien' là dấu hiệu trang giả mạo."))
    return flags


# Warnings like "KHÔNG cung cấp mã OTP cho bất kỳ ai" are advice, not a request.
NEGATION_RE = re.compile(r"\b(khong|dung|tuyet doi khong|khong bao gio|never|do not|don't)\b")
NEGATABLE = {"otp", "money_request"}


def _matches(flag_id: str, pattern: str, norm: str) -> bool:
    for m in re.finditer(pattern, norm):
        before = norm[max(0, m.start() - 35): m.start()]
        if flag_id in NEGATABLE and NEGATION_RE.search(before):
            continue
        return True
    return False


def find_flags(text: str) -> list[Flag]:
    norm = normalize(text)
    found: dict[str, Flag] = {}
    for flag, patterns in KEYWORD_RULES:
        if any(_matches(flag.id, p, norm) for p in patterns):
            found[flag.id] = flag
    for url in extract_urls(text):
        for flag in check_url(url):
            found.setdefault(flag.id, flag)
    return list(found.values())
