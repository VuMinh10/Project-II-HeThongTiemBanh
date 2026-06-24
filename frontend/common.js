// 1. Tự động tải Navbar và kiểm tra đăng nhập ngay khi mở trang
document.addEventListener('DOMContentLoaded', async () => {
    const navbarPlaceholder = document.getElementById('navbar-placeholder');
    
    if (navbarPlaceholder) {
        try {
            const response = await fetch('navbar.html');
            if (!response.ok) throw new Error('Không tìm thấy file navbar');
            
            const data = await response.text();
            navbarPlaceholder.innerHTML = data;
        } catch (error) {
            console.error('Lỗi tải Navbar:', error);
        }
    } 
    
    checkLoginState();
    updateCartBadge();
});

// 2. Hàm kiểm tra quyền và đổi giao diện Dropdown
function checkLoginState() {
    const userJson = localStorage.getItem('bakery_user');
    const authSection = document.getElementById('authSection');
    const btnLogin = document.getElementById('btnLogin');

    if (userJson && authSection) {
        const user = JSON.parse(userJson);
        if (btnLogin) btnLogin.style.display = 'none';

        // Xóa menu cũ nếu có 
        const existingMenu = document.getElementById('userDropdownMenu');
        if (existingMenu) existingMenu.remove();

        let userMenuHtml = `
            <div class="dropdown" id="userDropdownMenu">
                <button class="btn btn-light dropdown-toggle fw-bold" type="button" data-bs-toggle="dropdown">
                    <i class="fas fa-user-circle text-primary me-1"></i> Chào, ${user.fullName}
                </button>
                <ul class="dropdown-menu dropdown-menu-end shadow-sm">
        `;

        const currentRole = Number(user.roleId);
        // Menu riêng cho Admin (Role 2) và Nhân viên (Role 3)
        if (currentRole === 2) {
            userMenuHtml += `<li><a class="dropdown-item text-primary fw-bold" href="admin-dashboard.html"><i class="fas fa-cogs me-2"></i>Trang Quản Trị</a></li>`;
        } else if (currentRole === 3) {
            userMenuHtml += `<li><a class="dropdown-item text-success fw-bold" href="pos.html"><i class="fas fa-cash-register me-2"></i>Màn Hình POS</a></li>`;
        }
        
        // Thêm dòng kẻ ngang phân cách nếu là nội bộ
        if (currentRole === 2 || currentRole === 3) {
            userMenuHtml += `<li><hr class="dropdown-divider"></li>`;
        }

        // Menu chung cho mọi khách hàng
        userMenuHtml += `
                    <li><a class="dropdown-item" href="profile.html"><i class="fas fa-user me-2"></i>Thông tin cá nhân</a></li>
                    <li><a class="dropdown-item" href="order-history.html"><i class="fas fa-receipt me-2"></i>Đơn hàng của tôi</a></li>
                    <li><hr class="dropdown-divider"></li>
                    <li><a class="dropdown-item text-danger" href="#" onclick="logout()"><i class="fas fa-sign-out-alt me-2"></i>Đăng xuất</a></li>
                </ul>
            </div>
        `;

        authSection.insertAdjacentHTML('beforeend', userMenuHtml);
    }
}

// 3. Hàm đăng xuất
window.logout = function() {
    if (confirm('Bạn có chắc chắn muốn đăng xuất khỏi hệ thống?')) {
        // Xóa dữ liệu phiên đăng nhập
        localStorage.removeItem('bakery_token');
        localStorage.removeItem('bakery_user');
        
        // Xóa luôn giỏ hàng của người này để khách sau dùng máy không thấy
        sessionStorage.removeItem('bakery_cart'); 
        
        // Dùng replace để khách không bấm nút "Back" trên trình duyệt để quay lại trang cũ được
        window.location.replace('login.html'); 
    }
};

// 4. Hàm cập nhật số lượng giỏ hàng trên Navbar 
window.updateCartBadge = function() {
    const cartBadge = document.getElementById('cartBadge');
    if (cartBadge) {
        let cart = JSON.parse(sessionStorage.getItem('bakery_cart')) || [];
        const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
        
        cartBadge.innerText = totalItems;

        // Đổi màu huy hiệu thành đỏ nếu có hàng để thu hút ánh nhìn
        if (totalItems > 0) {
            cartBadge.classList.replace('bg-secondary', 'bg-danger');
        } else {
            cartBadge.classList.replace('bg-danger', 'bg-secondary');
        }
    }
};