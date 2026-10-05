"""Basic tests. Run with:  python -m pytest tests   (or)   python tests/test_detector.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from safecheck.anonymize import redact  # noqa: E402
from safecheck.detector import Detector  # noqa: E402
from safecheck.rules import extract_urls, find_flags, normalize  # noqa: E402

detector = Detector()

# Messages NOT in the training data
SCAMS = [
    "Tai khoan Agribank cua ban bi khoa. Xac minh ngay tai agribank-baomat.xyz truoc 12h",
    "Con ơi mẹ bị mất điện thoại, đây là số mới, con chuyển gấp cho mẹ 2 triệu vào tài khoản này nhé",
    "Tôi có video riêng tư của bạn, chuyển 5 triệu nếu không tôi sẽ phát tán cho bạn bè bạn",
    "Cán bộ công an yêu cầu bạn cài ứng dụng theo đường link để phục vụ điều tra, không được báo người thân",
]
SAFE = [
    "Mai nhóm mình họp lúc 9h ở thư viện nhé",
    "Ma OTP cua ban la 123456. Khong cung cap ma nay cho bat ky ai.",
    "Nhớ bật xác thực hai lớp và đổi mật khẩu Facebook nhé",
    "Xem ảnh lớp mình ở đây: https://photos.google.com/share/abc",
]


def test_normalize_strips_accents():
    assert normalize("Tài Khoản ĐÃ bị khóa") == "tai khoan da bi khoa"


def test_extract_urls_ignores_numbers():
    assert extract_urls("Chuyển 5.000.000đ, biển số 29A-123.45") == []
    assert extract_urls("vào bidv-capnhat.xyz ngay") == ["bidv-capnhat.xyz"]


def test_lookalike_domain_flagged():
    ids = {f.id for f in find_flags("Xác minh tại vietcombank-xacminh.top")}
    assert {"brand_lookalike", "risky_tld"} <= ids


def test_bracketed_link_does_not_crash():
    # real SMS sometimes wrap links in [ ]; urlparse used to raise "Invalid IPv6 URL"
    msg = "Xac nhan dia chi giao hang tai link: [http://shopee.qua-tri-an.top]"
    assert "brand_lookalike" in {f["id"] for f in detector.check(msg)["flags"]}


def test_official_domain_not_flagged():
    assert find_flags("Xem tại https://www.vietcombank.com.vn") == []


def test_http_is_weak_flag_and_https_is_not_trusted():
    assert "no_https" in {f.id for f in find_flags("Đăng nhập tại http://capnhat-taikhoan.com")}
    assert "no_https" not in {f.id for f in find_flags("Đăng nhập tại https://capnhat-taikhoan.com")}
    # https never protects a fake brand domain
    assert "brand_lookalike" in {f.id for f in find_flags("https://vietcombank-xacminh.top")}


def test_otp_warning_is_not_a_request():
    assert "otp" not in {f.id for f in find_flags("Tuyệt đối không cung cấp mã OTP cho ai")}
    assert "otp" in {f.id for f in find_flags("Bạn đọc giúp mình mã OTP nhé")}


def test_scams_are_high_risk():
    for msg in SCAMS:
        result = detector.check(msg)
        assert result["level"] == "high", (result["score"], msg)


def test_safe_messages_are_low_risk():
    for msg in SAFE:
        result = detector.check(msg)
        assert result["level"] == "low", (result["score"], msg)


def test_redact_removes_personal_numbers():
    assert redact("Gọi 0912 345 678 hoặc +84 987654321") == "Gọi [SĐT] hoặc [SĐT]"
    assert redact("Liên hệ Zalo 0987xxxxxx ngay") == "Liên hệ Zalo [SĐT] ngay"
    assert redact("STK 19036812345678 Techcombank") == "STK [SỐ TK] Techcombank"
    assert redact("Số thẻ 4111 1111 1111 1111") == "Số thẻ [SỐ THẺ]"
    assert redact("Mã OTP là 482913, không chia sẻ") == "Mã OTP là [MÃ], không chia sẻ"
    assert redact("TK 1023xxxx789 +500,000VND") == "TK [SỐ TK] +500,000VND"
    assert redact("Email nguyenvana@gmail.com") == "Email [EMAIL]"
    assert redact("Xác minh tại vcb-xacminh.top/login?id=88231&u=lan") == "Xác minh tại vcb-xacminh.top/login"


def test_redact_keeps_amounts_times_and_dates():
    msg = "Chuyển 5.000.000đ trước 14:30 ngày 05/10/2026, phí 25000đ, biển số 29A-123.45, năm 2026"
    assert redact(msg) == msg


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"\nAll {len(tests)} tests passed.")
