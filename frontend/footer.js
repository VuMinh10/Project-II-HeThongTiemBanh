document.addEventListener("DOMContentLoaded", function() {
    const footerContent = `
        <footer style="background-color: #333; color: white; padding: 20px; text-align: center; margin-top: 50px;">
            <div class="footer-info">
                <h3>SweetBakery</h3>
                <p>Địa chỉ: 123 Đường Cầu Giấy, Hà Nội</p>
                <p>Điện thoại: 0123.456.789</p>
                <p>Email: lienhe@tiembanh.com</p>
                <p>Facebook: <a href="https://facebook.com/sweetbakery" style="color: #ff99cc;">SweetBakery Fanpage</a></p>
            </div>
            <div style="margin-top: 10px; font-size: 14px;">
                © 2026 Bản quyền thuộc về SweetBakery.
            </div>
        </footer>
    `;

    const placeholder = document.getElementById("footer-placeholder");
    
    if (placeholder) {
        placeholder.innerHTML = footerContent;
    }
});