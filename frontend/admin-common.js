document.addEventListener('DOMContentLoaded', async () => {
    // 1. Bảo mật
    const token = localStorage.getItem('bakery_token');
    const userRaw = localStorage.getItem('bakery_user');

    if (!token || !userRaw) {
        window.location.replace('login.html');
        return;
    }

    const currentAdmin = JSON.parse(userRaw);
    if (currentAdmin.roleId !== 2) { // Phải là Admin (2) mới được vào
        alert('Truy cập bị từ chối!');
        window.location.replace('index.html');
        return;
    }

    // Mở khóa giao diện 
    document.body.style.display = 'block';

    // Hiệu ứng trượt để ẩn
    const style = document.createElement('style');
    style.innerHTML = `
        .sidebar {
            transition: all 0.3s ease-in-out;
            overflow: hidden;
            width: 250px;
        }
        .sidebar.collapsed {
            width: 0 !important;
            padding: 0 !important;
            opacity: 0;
        }
        .flex-grow-1 {
            transition: all 0.3s ease-in-out;
        }
    `;
    document.head.appendChild(style);

    // 2. Tải sidebar vào trang
    const sidebarPlaceholder = document.getElementById('admin-sidebar-placeholder');
    if (sidebarPlaceholder) {
        try {
            const response = await fetch('admin-sidebar.html');
            sidebarPlaceholder.outerHTML = await response.text();

            const sidebarElement = document.querySelector('.sidebar');
            
            // Tìm thanh tiêu đề của trang (Ví dụ: Chỗ chứa chữ "Quản lý Đơn hàng")
            const pageHeader = document.querySelector('.flex-grow-1 > .d-flex.justify-content-between');
            const titleH2 = pageHeader ? pageHeader.querySelector('h2') : null;

            if (pageHeader && titleH2 && sidebarElement) {
                titleH2.classList.add('mb-0');

                const wrapper = document.createElement('div');
                wrapper.className = 'd-flex align-items-center gap-3';
                
                // Tạo nút 3 gạch
                const toggleBtn = document.createElement('button');
                toggleBtn.className = 'btn btn-outline-dark shadow-sm';
                toggleBtn.innerHTML = '<i class="fas fa-bars"></i>';
                
                // Lắp ráp chúng lại với nhau vào trang web
                pageHeader.insertBefore(wrapper, titleH2);
                wrapper.appendChild(toggleBtn);
                wrapper.appendChild(titleH2); 

                // Khôi phục trạng thái bộ nhớ: Có đang bị ẩn từ trước không?
                if (localStorage.getItem('admin_sidebar_closed') === 'true') {
                    sidebarElement.classList.add('collapsed');
                }

                // Xử lý sự kiện khi bấm nút 3 gạch
                toggleBtn.addEventListener('click', () => {
                    sidebarElement.classList.toggle('collapsed'); // Bật/Tắt class ẩn
                    const isClosed = sidebarElement.classList.contains('collapsed');
                    localStorage.setItem('admin_sidebar_closed', isClosed); // Lưu vào não trình duyệt
                });
            }

            // 3. Tự động đánh dấu (active) menu đang xem
            let currentPath = window.location.pathname.split('/').pop(); 
            if (currentPath === '') currentPath = 'admin-dashboard.html';

            document.querySelectorAll('.sidebar a').forEach(link => {
                if (link.getAttribute('href') === currentPath) link.classList.add('active');
            });

            // 4. Kích hoạt nút Đăng xuất
            const btnLogout = document.getElementById('btnAdminLogout');
            if (btnLogout) {
                btnLogout.addEventListener('click', () => {
                    if (confirm('Thoát quản trị?')) {
                        localStorage.removeItem('bakery_token');
                        localStorage.removeItem('bakery_user');
                        sessionStorage.removeItem('bakery_cart');
                        window.location.replace('login.html');
                    }
                });
            }
        } catch (error) {
            console.error('Lỗi tải Sidebar:', error);
        }
    }
});