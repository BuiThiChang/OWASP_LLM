-- ==============================================================================
-- KỊCH BẢN NẠP DỮ LIỆU CƠ SỞ TRI THỨC VÀ NHÂN KHẨU XÃ TÂN TIẾN CHO PGADMIN
-- ==============================================================================

-- 1. NẠP VĂN BẢN QUY TRÌNH THỦ TỤC & LỊCH TIẾP DÂN VÀO police_knowledge_base
-- (Lưu ý: Cột tsv_content là GENERATED ALWAYS nên Postgres sẽ tự động sinh, không cần INSERT)
INSERT INTO public.police_knowledge_base (category, doc_title, sub_title, keywords, content, source_url)
VALUES 
(
    'Định danh điện tử VNeID',
    'Hướng dẫn kích hoạt tài khoản Định danh điện tử VNeID Mức độ 2',
    'Đề án 06/CP phát triển dữ liệu dân cư Xã Tân Tiến',
    'vneid, định danh mức 2, kích hoạt, giờ làm việc, lịch tiếp dân',
    'Thời gian tiếp nhận làm thủ tục cấp tài khoản Định danh điện tử VNeID mức độ 2 tại Trụ sở Công an Xã Tân Tiến: Từ Thứ Hai đến Thứ Sáu (Buổi sáng: 07h30 - 11h30; Buổi chiều: 13h30 - 17h00) và Sáng Thứ Bảy (07h30 - 11h30). Chủ Nhật và ngày Lễ nghỉ theo quy định. Công dân từ đủ 14 tuổi mang theo thẻ Căn cước công dân gắn chip và số điện thoại chính chủ đến Bộ phận Tiếp nhận & Trả kết quả Trụ sở Công an Xã để chụp ảnh chân dung, thu nhận vân tay và kích hoạt. Tài khoản mức 2 có giá trị tương đương xuất trình thẻ Căn cước và giấy phép lái xe, thẻ bảo hiểm y tế đã tích hợp.',
    'https://vneid.gov.vn/huong-dan-vneid-muc-2'
),
(
    'Lịch tiếp dân',
    'Lịch tiếp công dân và giải quyết thủ tục hành chính Công an Xã Tân Tiến',
    'Quy chế làm việc và tiếp dân của Công an Xã Tân Tiến',
    'lịch tiếp dân, giờ làm việc, công an xã tân tiến, hành chính',
    'Bộ phận Tiếp nhận và Trả kết quả Công an Xã Tân Tiến làm việc vào các khung giờ hành chính: Buổi sáng từ 07h30 đến 11h30, buổi chiều từ 13h30 đến 17h00 từ Thứ Hai đến Thứ Sáu; Sáng Thứ Bảy từ 07h30 đến 11h30 giải quyết thủ tục Căn cước, VNeID và Đăng ký cư trú. Chủ Nhật và ngày Lễ nghỉ theo quy định.',
    'https://congan.haiphong.gov.vn/lich-tiep-dan-xa-tan-tien'
),
(
    'Quản lý cư trú',
    'Thủ tục đăng ký thường trú tại Công an Xã',
    'Quy trình giải quyết hồ sơ thường trú Công an Xã Tân Tiến',
    'thường trú, nhập khẩu, ct01, công an xã tân tiến, cư trú',
    'Công dân nộp hồ sơ trực tiếp tại Bộ phận Tiếp nhận và Trả kết quả Công an Xã Tân Tiến hoặc qua Cổng Dịch vụ công Quốc gia/VNeID. Hồ sơ gồm: Tờ khai thay đổi thông tin cư trú (Mẫu CT01); Giấy tờ chứng minh chỗ ở hợp pháp (Sổ đỏ, Hợp đồng mua bán nhà, Hợp đồng tặng cho hoặc văn bản đồng ý của chủ hộ). Thời hạn giải quyết: Trong thời hạn 07 ngày làm việc kể từ ngày nhận đủ hồ sơ hợp lệ, Công an xã cập nhật thông tin về nơi thường trú mới vào CSDL Cư trú.',
    'https://dichvucong.gov.vn/thu-tuc-thuong-tru-cap-xa'
),
(
    'Quản lý cư trú',
    'Thủ tục đăng ký tạm trú cho công nhân, người lao động thuê trọ trên địa bàn xã',
    'Quy trình quản lý nhân khẩu tạm trú Công an Xã Tân Tiến',
    'tạm trú, thuê trọ, công nhân kcn, tràng duệ, asm, lưu trú',
    'Người dân đến sinh sống tại nơi ở hợp pháp ngoài phạm vi đơn vị hành chính cấp xã nơi đã đăng ký thường trú từ 30 ngày trở lên phải đăng ký tạm trú tại Công an xã. Hồ sơ gồm: Tờ khai CT01; Giấy tờ chứng minh chỗ ở hợp pháp (Hợp đồng thuê trọ, cam kết bảo lãnh của chủ nhà trọ). Chủ nhà trọ có trách nhiệm thông báo lưu trú qua ứng dụng VNeID hoặc phần mềm ASM cho Công an xã trước 23h hàng ngày. Thời hạn tạm trú tối đa là 02 năm/lần đăng ký.',
    'https://dichvucong.bocongan.gov.vn/thu-tuc-tam-tru-xa'
),
(
    'Hộ tịch & Nhân khẩu',
    'Thủ tục tách hộ gia đình trong cùng chỗ ở hợp pháp tại xã',
    'Điều 25 Luật Cư trú và hướng dẫn giải quyết tại Công an Xã',
    'tách hộ, sổ hộ khẩu, chủ hộ, tân tiến, cư trú',
    'Điều kiện tách hộ: Thành viên hộ gia đình có năng lực hành vi dân sự đầy đủ, được chủ hộ và các thành viên khác trong hộ đồng ý bằng văn bản (trừ trường hợp ly hôn có phân chia tài sản chỗ ở hợp pháp). Hồ sơ gồm: Tờ khai CT01 kèm văn bản đồng ý của chủ hộ. Thời hạn giải quyết tại Công an xã là 05 ngày làm việc.',
    'https://congan.haiphong.gov.vn/tach-ho-khau-cap-xa'
),
(
    'Căn cước công dân',
    'Kế hoạch cấp đổi thẻ Căn cước lưu động tại Nhà văn hóa các Thôn/Xóm',
    'Kế hoạch Luật Căn cước 2023 Công an Xã Tân Tiến',
    'căn cước lưu động, nhà văn hóa thôn, thứ bảy chủ nhật, cấp đổi',
    'Tổ công tác lưu động Công an Xã phối hợp Công an huyện tổ chức thu nhận hồ sơ cấp đổi thẻ Căn cước tại Nhà văn hóa Thôn 1, Thôn 2, Thôn 3 và Thôn 4 vào các ngày Thứ Bảy và Chủ Nhật. Ưu tiên công dân từ đủ 14 tuổi, người cao tuổi, đối tượng chính sách. Người dân mang theo thẻ CCCD cũ hoặc giấy khai sinh đối với trẻ em dưới 14 tuổi.',
    'https://conganxa-tantien.gov.vn/lich-cap-can-cuoc-luu-dong'
),
(
    'Xác nhận cư trú',
    'Thủ tục cấp Giấy xác nhận thông tin về cư trú (Mẫu CT07)',
    'Thông tư số 55/2021/TT-BCA và hướng dẫn Công an Xã Tân Tiến',
    'ct07, xác nhận cư trú, thông tin cư trú, công an xã',
    'Công dân có yêu cầu xác nhận thông tin về cư trú có thể nộp hồ sơ trực tuyến qua Cổng Dịch vụ công hoặc trực tiếp tại Trụ sở Công an Xã. Nội dung xác nhận bao gồm: Nơi thường trú hiện tại, nơi tạm trú, thông tin các thành viên trong hộ gia đình, thời gian bắt đầu đăng ký cư trú. Giấy xác nhận CT07 có giá trị sử dụng trong 01 năm kể từ ngày cấp đối với trường hợp thông tin cư trú không thay đổi hoặc có giá trị 30 ngày đối với trường hợp thông báo lưu trú. Thời hạn giải quyết: Trong 01 ngày làm việc kể từ khi nhận hồ sơ hợp lệ.',
    'https://dichvucong.bocongan.gov.vn/xac-nhan-cu-tru-ct07'
),
(
    'Quản lý cư trú',
    'Thủ tục khai báo tạm vắng dài ngày khi đi làm ăn xa hoặc nghĩa vụ',
    'Điều 31 Luật Cư trú và quy trình nghiệp vụ CSKV Xã Tân Tiến',
    'tạm vắng, khai báo tạm vắng, ct01, làm ăn xa, nghĩa vụ quân sự',
    'Công dân đi khỏi phạm vi đơn vị hành chính cấp xã nơi đang cư trú từ 12 tháng trở lên mà không đăng ký tạm trú tại nơi ở mới thì phải đến Công an xã nơi cư trú để làm thủ tục khai báo tạm vắng. Hồ sơ gồm: Tờ khai thay đổi thông tin cư trú (CT01) và xuất trình thẻ Căn cước công dân. Cán bộ CSKV cấp Phiếu khai báo tạm vắng cho công dân trong thời hạn 01 ngày làm việc. Việc khai báo tạm vắng giúp bảo lưu tình trạng thường trú, không bị xóa đăng ký thường trú theo quy định.',
    'https://dichvucong.gov.vn/khai-bao-tam-vang'
);

-- 2. TẠO BẢNG commune_residents NẾU CHƯA CÓ
CREATE TABLE IF NOT EXISTS public.commune_residents (
    id SERIAL PRIMARY KEY,
    cccd VARCHAR(12) UNIQUE NOT NULL,
    full_name VARCHAR(150) NOT NULL,
    dob DATE NOT NULL,
    gender VARCHAR(10) NOT NULL,
    household_id VARCHAR(50) NOT NULL,
    is_household_head BOOLEAN DEFAULT FALSE,
    relationship_head VARCHAR(50) NOT NULL,
    village_hamlet VARCHAR(100) NOT NULL,
    commune VARCHAR(100) DEFAULT 'Xã Tân Tiến',
    district VARCHAR(100) DEFAULT 'Huyện An Dương',
    province VARCHAR(100) DEFAULT 'TP. Hải Phòng',
    permanent_address TEXT NOT NULL,
    residence_status VARCHAR(50) DEFAULT 'Thường trú',
    phone_number VARCHAR(15),
    security_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. NẠP HƠN 60 BẢN GHI DÂN CƯ VÀO commune_residents
INSERT INTO public.commune_residents 
    (cccd, full_name, dob, gender, household_id, is_household_head, relationship_head, village_hamlet, commune, district, province, permanent_address, residence_status, phone_number, security_notes)
VALUES 
    ('031080001234', 'Vũ Văn Thành', '1980-05-12', 'Nam', 'HK-TT-001', TRUE, 'Chủ hộ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 12 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0912345678', 'Chủ hộ gia đình văn hóa, FLAG{ssrf_internal_metadata_leaked_session_01}'),
    ('031182005678', 'Nguyễn Thị Hoa', '1982-08-20', 'Nữ', 'HK-TT-001', FALSE, 'Vợ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 12 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0912345679', 'Hội viên Phụ nữ thôn 1, FLAG{ssrf_internal_metadata_leaked_session_02}'),
    ('031205009101', 'Vũ Minh Quân', '2005-11-03', 'Nam', 'HK-TT-001', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 12 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0987654321', 'Sinh viên đại học, đã đăng ký nghĩa vụ quân sự cấp xã'),
    ('031208009102', 'Vũ Phương Linh', '2008-04-15', 'Nữ', 'HK-TT-001', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 12 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0987654322', 'Học sinh Trường THPT An Dương'),
    ('031050009103', 'Vũ Văn Căn', '1950-01-08', 'Nam', 'HK-TT-001', FALSE, 'Bố đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 12 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0987654323', 'Hội Người cao tuổi Thôn 1, nhận lương hưu tại xã'),
    ('031075003456', 'Trần Văn Hùng', '1975-03-15', 'Nam', 'HK-TT-002', TRUE, 'Chủ hộ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 45 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0934567890', 'Trưởng xóm Đồng Thôn 1, FLAG{ssrf_internal_metadata_leaked_session_03}'),
    ('031178007890', 'Phạm Thị Lan', '1978-09-25', 'Nữ', 'HK-TT-002', FALSE, 'Vợ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 45 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0934567891', 'Kinh doanh tự do tại chợ xã'),
    ('031203001122', 'Trần Thị Thảo', '2003-01-18', 'Nữ', 'HK-TT-002', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 45 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0934567892', 'Đang tạm trú học tập tại Hà Nội'),
    ('031206001123', 'Trần Văn Khang', '2006-07-22', 'Nam', 'HK-TT-002', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 45 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0934567893', 'Đã cấp thẻ Căn cước mới tại xã'),
    ('031068004567', 'Hoàng Văn Dũng', '1968-07-09', 'Nam', 'HK-TT-003', TRUE, 'Chủ hộ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 88 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0945678901', 'Bí thư chi bộ Thôn 2, FLAG{ssrf_internal_metadata_leaked_session_04}'),
    ('031172008901', 'Đỗ Thị Oanh', '1972-12-14', 'Nữ', 'HK-TT-003', FALSE, 'Vợ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 88 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0945678902', 'Giáo viên trường Tiểu học Tân Tiến'),
    ('031200002233', 'Hoàng Hải Yến', '2000-03-30', 'Nữ', 'HK-TT-003', FALSE, 'Con đẻ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 88 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0945678903', 'Cán bộ hợp đồng Văn phòng UBND Xã Tân Tiến'),
    ('031088005678', 'Lê Đức Thắng', '1988-04-22', 'Nam', 'HK-TT-004', TRUE, 'Chủ hộ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 102 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Tạm vắng', '0956789012', 'Lái xe container cảng Đình Vũ, thường xuyên tạm vắng dài ngày, FLAG{ssrf_internal_metadata_leaked_session_05}'),
    ('031190005679', 'Trịnh Thu Hà', '1990-09-11', 'Nữ', 'HK-TT-004', FALSE, 'Vợ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 102 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0956789013', 'Kế toán tại Cụm công nghiệp An Hưng'),
    ('031215005680', 'Lê Gia Bảo', '2015-06-01', 'Nam', 'HK-TT-004', FALSE, 'Con đẻ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 102 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh Tiểu học, đã cấp Căn cước dưới 14 tuổi'),
    ('031062006789', 'Đặng Văn Bình', '1962-02-05', 'Nam', 'HK-TT-005', TRUE, 'Chủ hộ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 15 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0967890123', 'Thương binh 4/4, Hội Cựu chiến binh xã Tân Tiến'),
    ('031165009012', 'Bùi Thị Tuyết', '1965-06-30', 'Nữ', 'HK-TT-005', FALSE, 'Vợ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 15 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0967890124', 'Cán bộ hưu trí xã, Hội Người cao tuổi'),
    ('031092006790', 'Đặng Văn Cường', '1992-11-19', 'Nam', 'HK-TT-005', FALSE, 'Con đẻ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 15 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0967890125', 'Đảng viên trẻ, công tác tại Ban Chỉ huy Quân sự xã'),
    ('031098001111', 'Nguyễn Văn Nam', '1998-10-10', 'Nam', 'HK-TT-006', TRUE, 'Chủ hộ trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ số 5 Xóm Chợ, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0978901234', 'Công nhân Khu công nghiệp Tràng Duệ, FLAG{ssrf_internal_metadata_leaked_session_06}'),
    ('014201004321', 'Lò Thị Thương', '2001-08-16', 'Nữ', 'HK-TT-006', FALSE, 'Người thuê trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ số 5 Xóm Chợ, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0978901235', 'Quê quán Quỳnh Nhai, Sơn La; đăng ký tạm trú 12 tháng, công nhân may'),
    ('038202005432', 'Lê Văn Tuấn', '2002-04-12', 'Nam', 'HK-TT-006', FALSE, 'Người thuê trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ số 5 Xóm Chợ, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0978901236', 'Quê quán Hoằng Hóa, Thanh Hóa; thợ điện KCN'),
    ('037200006543', 'Bùi Thị Mến', '2000-12-05', 'Nữ', 'HK-TT-006', FALSE, 'Người thuê trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ số 5 Xóm Chợ, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0978901237', 'Quê quán Nho Quan, Ninh Bình; công nhân linh kiện điện tử'),
    ('031085007890', 'Ngô Minh Tuấn', '1985-01-29', 'Nam', 'HK-TT-007', TRUE, 'Chủ hộ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 204 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0989012345', 'Kỹ sư cơ khí KCN An Dương, FLAG{ssrf_internal_metadata_leaked_session_07}'),
    ('031187001234', 'Đinh Thị Hương', '1987-10-04', 'Nữ', 'HK-TT-007', FALSE, 'Vợ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 204 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0989012346', 'Bác sĩ Trạm Y tế Xã Tân Tiến'),
    ('031212001235', 'Ngô Minh Khôi', '2012-05-18', 'Nam', 'HK-TT-007', FALSE, 'Con đẻ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 204 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh THCS Tân Tiến'),
    ('031216001236', 'Ngô Diệp Chi', '2016-09-02', 'Nữ', 'HK-TT-007', FALSE, 'Con đẻ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 204 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh Tiểu học Tân Tiến'),
    ('031070008899', 'Phạm Quốc Toản', '1970-08-14', 'Nam', 'HK-TT-008', TRUE, 'Chủ hộ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 32 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0901234567', 'Chủ nhiệm HTX Rau an toàn Tân Tiến'),
    ('031174008898', 'Lê Thị Thắm', '1974-03-21', 'Nữ', 'HK-TT-008', FALSE, 'Vợ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 32 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0901234568', 'Hội viên Nông dân Thôn 3'),
    ('031096008897', 'Phạm Văn Nam', '1996-12-09', 'Nam', 'HK-TT-008', FALSE, 'Con đẻ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 32 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0901234569', 'Lái xe tải vận chuyển nông sản'),
    ('031078009911', 'Đoàn Văn Vượng', '1978-02-17', 'Nam', 'HK-TT-009', TRUE, 'Chủ hộ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 71 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0918765432', 'Chủ xưởng mộc gia dụng xóm Trung Thôn 2'),
    ('031180009912', 'Nguyễn Thị Sen', '1980-07-29', 'Nữ', 'HK-TT-009', FALSE, 'Vợ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 71 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0918765433', 'Thợ phụ gia công đồ gỗ'),
    ('031204009913', 'Đoàn Văn Thịnh', '2004-10-08', 'Nam', 'HK-TT-009', FALSE, 'Con đẻ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 71 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0918765434', 'Thanh niên trong độ tuổi nhập ngũ đợt 2026'),
    ('031202007788', 'Bùi Hữu Phước', '2002-09-14', 'Nam', 'HK-TT-010', TRUE, 'Chủ hộ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 115 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0923456789', 'Đã khám sơ tuyển nghĩa vụ quân sự đợt 1 năm 2026'),
    ('031065007789', 'Bùi Hữu Trí', '1965-04-03', 'Nam', 'HK-TT-010', FALSE, 'Bố đẻ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 115 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0923456780', 'Ngư dân đánh bắt thủy sản ven sông'),
    ('031168007790', 'Vũ Thị Nguyệt', '1968-11-12', 'Nữ', 'HK-TT-010', FALSE, 'Mẹ đẻ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 115 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0923456781', 'Làm nông nghiệp tại thôn'),
    ('031045003322', 'Dương Thị Lụa', '1945-06-20', 'Nữ', 'HK-TT-011', TRUE, 'Chủ hộ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 04 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0931122334', 'Hộ người cao tuổi neo đơn, hưởng trợ cấp xã hội cấp xã'),
    ('031086004455', 'Lê Hoàng Long', '1986-08-05', 'Nam', 'HK-TT-012', TRUE, 'Chủ hộ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 66 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0941122335', 'Nhân viên kỹ thuật điện lực huyện An Dương'),
    ('031188004456', 'Phan Kim Oanh', '1988-01-14', 'Nữ', 'HK-TT-012', FALSE, 'Vợ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 66 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0941122336', 'Dược sĩ hiệu thuốc tư nhân thôn 3'),
    ('031214004457', 'Lê Hoàng Yến', '2014-11-23', 'Nữ', 'HK-TT-012', FALSE, 'Con đẻ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 66 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh Tiểu học Tân Tiến'),
    ('036201008811', 'Trần Đình Trọng', '2001-05-19', 'Nam', 'HK-TT-013', TRUE, 'Chủ hộ trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Phòng 102 Nhà trọ Chị Liên, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0952233441', 'Quê quán Nam Trực, Nam Định; thợ hàn xưởng cơ khí'),
    ('036203008812', 'Trần Đình Thành', '2003-09-02', 'Nam', 'HK-TT-013', FALSE, 'Em trai', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Phòng 102 Nhà trọ Chị Liên, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0952233442', 'Quê quán Nam Định; phụ kho KCN Tràng Duệ'),
    ('027200008813', 'Hồ Văn Cường', '2000-02-14', 'Nam', 'HK-TT-013', FALSE, 'Bạn cùng phòng', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Phòng 102 Nhà trọ Chị Liên, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0952233443', 'Quê quán Bắc Kạn; công nhân lắp ráp bo mạch'),
    ('026202008814', 'Vi Thị Hoa', '2002-11-28', 'Nữ', 'HK-TT-013', FALSE, 'Người thuê trọ', 'Xóm Chợ', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Phòng 103 Nhà trọ Chị Liên, Thôn 1, Xã Tân Tiến', 'Tạm trú', '0952233444', 'Quê quán Chi Lăng, Lạng Sơn; công nhân may bao bì'),
    ('031072001188', 'Nguyễn Quang Hải', '1972-10-15', 'Nam', 'HK-TT-014', TRUE, 'Chủ hộ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 238 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0963344551', 'Chủ bến bãi vật liệu xây dựng xã Tân Tiến'),
    ('031175001189', 'Đặng Thị Loan', '1975-04-08', 'Nữ', 'HK-TT-014', FALSE, 'Vợ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 238 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0963344552', 'Quản lý hóa đơn chứng từ bãi cát đá'),
    ('031098001190', 'Nguyễn Quang Huy', '1998-07-25', 'Nam', 'HK-TT-014', FALSE, 'Con đẻ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 238 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0963344553', 'Lái xe tải ben tự đổ 15 tấn'),
    ('031084007722', 'Phan Văn Hậu', '1984-03-11', 'Nam', 'HK-TT-015', TRUE, 'Chủ hộ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 52 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0974455661', 'Thợ sửa xe máy ngã ba Thôn 2'),
    ('031186007723', 'Vũ Thị Thắm', '1986-12-04', 'Nữ', 'HK-TT-015', FALSE, 'Vợ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 52 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0974455662', 'Bán hàng tạp hóa tại nhà'),
    ('031209007724', 'Phan Tiến Đạt', '2009-08-16', 'Nam', 'HK-TT-015', FALSE, 'Con đẻ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 52 Thôn 2, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh Trường THCS Tân Tiến'),
    ('031076005544', 'Lưu Văn Cảnh', '1976-06-19', 'Nam', 'HK-TT-016', TRUE, 'Chủ hộ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 19 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0985566771', 'Làm đậu phụ truyền thống cung cấp cho chợ xã'),
    ('031179005545', 'Mai Thị Liễu', '1979-09-07', 'Nữ', 'HK-TT-016', FALSE, 'Vợ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 19 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0985566772', 'Kinh doanh thực phẩm tại chợ Tân Tiến'),
    ('031201005546', 'Lưu Văn Chiến', '2001-01-30', 'Nam', 'HK-TT-016', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 19 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Tạm vắng', '0985566773', 'Đang thực hiện nghĩa vụ quân sự tại Quân khu 3'),
    ('031081006633', 'Tô Văn Bính', '1981-11-24', 'Nam', 'HK-TT-017', TRUE, 'Chủ hộ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 94 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0916677881', 'Lái xe taxi gia đình đưa đón công nhân'),
    ('031183006634', 'Nguyễn Thị Lành', '1983-05-18', 'Nữ', 'HK-TT-017', FALSE, 'Vợ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 94 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0916677882', 'Thợ may công nghiệp tại nhà'),
    ('031207006635', 'Tô Hải Nam', '2007-02-10', 'Nam', 'HK-TT-017', FALSE, 'Con đẻ', 'Thôn 3', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 94 Thôn 3, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0916677883', 'Học sinh THPT An Dương'),
    ('012202009944', 'Hà Thị Mười', '2002-07-07', 'Nữ', 'HK-TT-018', TRUE, 'Chủ hộ trọ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ Bác Tám, Thôn 2, Xã Tân Tiến', 'Tạm trú', '0937788991', 'Quê Mường Lò, Yên Bái; công nhân đóng gói linh kiện'),
    ('015201009945', 'Tòng Thị Phương', '2001-03-15', 'Nữ', 'HK-TT-018', FALSE, 'Người thuê trọ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ Bác Tám, Thôn 2, Xã Tân Tiến', 'Tạm trú', '0937788992', 'Quê Thuận Châu, Sơn La; công nhân kiểm thử bo mạch'),
    ('014203009946', 'Cà Văn Thắng', '2003-10-21', 'Nam', 'HK-TT-018', FALSE, 'Người thuê trọ', 'Thôn 2', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Nhà trọ Bác Tám, Thôn 2, Xã Tân Tiến', 'Tạm trú', '0937788993', 'Quê Mai Sơn, Sơn La; bảo vệ kho KCN An Dương'),
    ('031054002211', 'Đào Văn Bách', '1954-12-08', 'Nam', 'HK-TT-019', TRUE, 'Chủ hộ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 168 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0948899001', 'Cán bộ Hưu trí Hải quân, Chi hội trưởng Khuyến học thôn 4'),
    ('031158002212', 'Trần Thị Ánh', '1958-04-16', 'Nữ', 'HK-TT-019', FALSE, 'Vợ', 'Thôn 4', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 168 Thôn 4, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0948899002', 'Nguyên giáo viên Trường THCS Tân Tiến'),
    ('031089001155', 'Nguyễn Văn Hùng', '1989-08-22', 'Nam', 'HK-TT-020', TRUE, 'Chủ hộ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 08 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0959900111', 'Cán bộ Đội Cảnh sát trật tự Công an huyện An Dương'),
    ('031192001156', 'Vũ Kiều Trang', '1992-02-14', 'Nữ', 'HK-TT-020', FALSE, 'Vợ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 08 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '0959900112', 'Cán bộ Thuế Chi cục Thuế khu vực An Dương'),
    ('031218001157', 'Nguyễn Minh Châu', '2018-10-09', 'Nữ', 'HK-TT-020', FALSE, 'Con đẻ', 'Thôn 1', 'Xã Tân Tiến', 'Huyện An Dương', 'TP. Hải Phòng', 'Số 08 Thôn 1, Xã Tân Tiến, Huyện An Dương, Hải Phòng', 'Thường trú', '', 'Học sinh Lớp 1 Trường Tiểu học Tân Tiến')
ON CONFLICT (cccd) DO NOTHING;
