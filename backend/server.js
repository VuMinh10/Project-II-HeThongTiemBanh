require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

/--------/
const path = require('path'); // Gọi thư viện đường dẫn
/--------/

const app = express();

// Mỗi khi có request thì phải đi qua trạm gac use()
app.use(cors()); // Chạm gác đầu tiên cors() kiểm tra
app.use(express.json()); /* Chạm thứ 2 kiểm tra xem dl gửi lên có phải json ko và nếu đúng 
chuyển thành object để mình đọc được */

/--------/
app.use(express.static(path.join(__dirname, '../frontend')));
/--------/

// -- Chuẩn bị đường ống kết nối database --
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost', // process là tiến trình sẽ chạy chương trình từ đầu rồi mới truy cập vào .env
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'test',
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 10, // max idle connections, the default value is the same as `connectionLimit`
  idleTimeout: 60000, // idle connections timeout, in milliseconds, the default value 60000
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0,
});

// -- Chạy thử một đường ống xem được ko --
pool.getConnection() // Xin một kết nối
    .then(function(connection) {
        console.log("Kết nối Database thành công.");
        connection.release(); // Giải phóng kết nối
    })
    .catch(function(err) {
        console.error("Kết nối Database thất bại", err.message);
        process.exit(1);
    });

// Kiểm tra token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization']; // Lấy phần chứa token trong headers
    const token = authHeader && authHeader.split(' ')[1];

    if(!token){
        return res.status(401).json({error: 'Không có quyền truy cập. Vui lòng đăng nhập.'});
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if(err){
            return res.status(403).json({ error: 'Phiên đăng nhập hết hạn hoặc không hợp lệ.' });
        }

        // Ko lỗi, cho đi
        req.user = user;
        next();
    });
};

// Kiểm tra quyền Admin
const isAdmin = (req, res, next) => {
    if(!req.user){
        return res.status(401).json({error: 'Không tìm thấy thông tin xác thực.'})
    }

    if(req.user.roleId !== 2){ // Quản trị viên có RoleID = 2
        return res.status(403).json({ error: 'Truy cập bị từ chối do không phải quản trị viên.' });
    }

    next();
};

// -- API đăng kí tài khoản --
app.post('/api/register', async(req, res) => {
    const { username, password, fullName, phone, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ error: 'Vui lòng nhập đủ các trường bắt buộc.' });
    }

    // Xin kết nối riêng để chạy Transaction
    const connection = await pool.getConnection(); 
    
    try {
        await connection.beginTransaction(); 

        const hashedPassword = await bcrypt.hash(password, 10); // Băm mật khẩu
        const roleId = 1; 

        // BƯỚC 1: Lưu bảng User
        const sqlUser = 'INSERT INTO User (Username, Password, FullName, Phone, Email, RoleID) VALUES (?, ?, ?, ?, ?, ?)';
        const [userResult] = await connection.execute(sqlUser, [username, hashedPassword, fullName, phone || null, email, roleId]);
        
        const newUserId = userResult.insertId;

        // BƯỚC 2: Khởi tạo hồ sơ Customer
        const sqlCustomer = 'INSERT INTO Customer (UserID, MembershipPoint) VALUES (?, ?)';
        await connection.execute(sqlCustomer, [newUserId, 0]);

        // BƯỚC 3: Xác nhận lưu toàn bộ
        await connection.commit(); 

        res.status(201).json({message: 'Đăng ký tài khoản thành công!'});

    } catch (error) {
        // Hủy bỏ toàn bộ thao tác nếu rớt ở Bước 1 hoặc Bước 2
        await connection.rollback(); 
        console.error('[Register Transaction Error]:', error);

        // Bắt lỗi trùng dữ liệu
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({error: 'Username hoặc Email đã tồn tại trong hệ thống.'});
        }

        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });

    } finally {
        // Luôn trả kết nối lại cho pool
        connection.release(); 
    }
});

// -- API đăng nhập -- (XXX)
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // 1. Kiểm tra dữ liệu đầu vào
        if (!username || !password) {
            return res.status(400).json({ error: 'Vui lòng nhập đầy đủ tài khoản và mật khẩu.' });
        }

        // 2. Truy vấn người dùng
        const sql = 'SELECT * FROM User WHERE Username = ?';
        const [users] = await pool.execute(sql, [username]);
        
        const user = users[0];

        // 3. Xác thực tài khoản và mật khẩu 
        if (!user || !(await bcrypt.compare(password, user.Password))) {
            return res.status(401).json({ error: 'Tài khoản hoặc mật khẩu không chính xác.' });
        }

        // 4. Tạo JWT Token
        const token = jwt.sign(
            { userId: user.UserID, roleId: user.RoleID },
            process.env.JWT_SECRET,
            { expiresIn: '1d' } 
        );

        // 5. Trả về kết quả 
        res.status(200).json({
            message: 'Đăng nhập thành công',
            token: token,
            user: {
                id: user.UserID,
                username: user.Username,
                fullName: user.FullName,
                roleId: user.RoleID
            }
        });

    } catch (error) {
        console.error('[Login API Error]:', error);
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });
    }
});

// -- API lấy profile -- (XXX)
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const sql = 'SELECT UserID, Username, FullName, Phone, Email FROM User WHERE UserID = ?';
        const [users] = await pool.execute(sql, [req.user.userId]);

        // Phòng trường hợp token chưa hết hạn nhưng tài khoản ko còn
        if (users.length === 0) {
            return res.status(404).json({ error: 'Không tìm thấy thông tin người dùng.' });
        }

        res.status(200).json({
            message: 'Lấy thông tin thành công',
            profile: users[0]
        });

    } catch (error) {
        console.error('[Profile API Error]:', error);
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });
    }
});

// -- API quản lý danh mục --
// 1. Lấy danh sách danh mục
app.get('/api/categories', async (req, res) => {
    try {
        const [categories] = await pool.execute('SELECT * FROM CATEGORY');
        res.status(200).json(categories);
    } catch (error) {
        console.error('[GET Categories Error]:', error); // Báo lỗi trên terminal máy tính
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});

// 2. Thêm danh mục mới (cần đăng nhập + admin)
app.post('/api/categories', authenticateToken, isAdmin, async(req, res) => {
    try {
        const {categoryName, description} = req.body; // Chuẩn hóa chữ thường

        if(!categoryName || categoryName.trim() === ''){ // trim() xóa dấu cách đầu cuối
            return res.status(400).json({error: 'Tên danh mục không được để trống.'});
        }

        const sql = 'INSERT INTO Category (CategoryName, Description) VALUES (?, ?)';
        const [result] = await pool.execute(sql, [categoryName, description || '']);

        res.status(200).json({message: 'Thêm mới danh mục thành công!'});

    } catch (error) {
        console.error('[POST Categories Error]:', error);
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }

});

// 3. Update danh mục (đăng nhập + admin)
app.put('/api/categories/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const {id} = req.params;
        const {categoryName, description} = req.body;

        if (!categoryName || categoryName.trim() === '') {
            return res.status(400).json({ error: 'Tên danh mục không được để trống.'});
        }

        const sql = 'UPDATE Category SET CategoryName = ?, Description = ? WHERE CategoryID = ?';
        const [result] = await pool.execute(sql, [categoryName, description || '', id]);

        // Nếu danh mục ko tồn tại
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Không tìm thấy danh mục này để cập nhật.' });
        }

        res.status(200).json({message: 'Cập nhật danh mục thành công!'});

    } catch (error) {
        console.error('[PUT Category Error]:', error);
        
        // Lỗi trùng tên danh mục
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({error: 'Tên danh mục này đã tồn tại, vui lòng chọn tên khác.'});
        }

        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });
    }
});

// 4. Xóa danh mục (cần đăng nhập + admin)
app.delete('/api/categories/:id', authenticateToken, isAdmin, async(req, res) => {
    try {
        const {id} = req.params;
        const [result] = await pool.execute('DELETE FROM Category WHERE CategoryID = ?', [id]);

        if(result.affectedRows === 0){
            return res.status(404).json({ error: 'Không tìm thấy danh mục để xóa.' });        
        }
        
        res.status(200).json({ message: 'Xóa danh mục thành công.' });

    } catch (error) {
        console.error('[DELETE Category Error]:', error);
        
        // Bắt chính xác mã lỗi Khóa ngoại
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
            return res.status(409).json({ error: 'Không thể xóa! Đang có sản phẩm thuộc danh mục này.' });
        }
        
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});

// -- API quản lý sản phẩm -- 
// 1. Lấy danh sách
app.get('/api/products', async (req, res) => {
    try {
        const sql = `
            SELECT p.*, c.CategoryName
            FROM Product p 
            LEFT JOIN Category c ON p.CategoryID = c.CategoryID
        `;

        const [products] = await pool.execute(sql);
        res.status(200).json(products);

    } catch (error) {
        console.error('[GET Products Error]:', error);
        res.status(500).json({error: 'Lỗi máy chủ nội bộ.'});
    }
});

// 2. Thêm sản phẩm (đăng nhập + admin)
app.post('/api/products', authenticateToken, isAdmin, async (req, res) => {
    try {
        const {productName, categoryId, price, description, 
                imageUrl, status, quantityAvailable, isPreOrder} 
        = req.body;
        
        if (!productName || !categoryId || price === undefined) {
            return res.status(400).json({error: 'Vui lòng nhập đầy đủ Tên, Danh mục và Giá sản phẩm.'});
        }

        const sql = `
            INSERT INTO Product 
            (ProductName, Description, ImageURL, Price, CategoryID, Status, QuantityAvailable, IsPreOrder) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;

        const [result] = await pool.execute(sql, [
            productName, 
            description || '', 
            imageUrl || '',
            price, 
            categoryId,  
            status || 'Còn bán',
            quantityAvailable || 0, 
            isPreOrder || 0
        ]);
        
        res.status(201).json({message: 'Thêm sản phẩm thành công!', productId: result.insertId});

    } catch (error) {
        console.error('[POST Product Error]:', error);

        // Lỗi nếu chọn sai CategoryID không tồn tại
        if (error.code === 'ER_NO_REFERENCED_ROW_2') {
            return res.status(400).json({error: 'Danh mục không tồn tại. Vui lòng kiểm tra lại.'});
        }

        res.status(500).json({ error: 'Lỗi máy chủ nội bộ.' });
    }
});

// 3. Cập nhập sản phẩm (đăng nhập + admin)
app.put('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;

        const { 
            productName, description, imageUrl, price,
            categoryId, status, quantityAvailable, isPreOrder 
        } = req.body;

        if (!productName || !categoryId || price === undefined) {
            return res.status(400).json({error: 'Vui lòng nhập đầy đủ Tên, Danh mục và Giá sản phẩm.'});
        }

        const sql = `
            UPDATE Product 
            SET ProductName=?, Description=?, ImageURL=?, Price=?,
            CategoryID=?, Status=?, QuantityAvailable=?, IsPreOrder=? 
            WHERE ProductID=?
        `;
        const [result] = await pool.execute(sql, [
            productName, description || '', imageUrl || '', price, 
            categoryId, status, quantityAvailable, isPreOrder, id
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).json({error: 'Không tìm thấy sản phẩm để cập nhật.'});
        }

        res.status(200).json({message: 'Cập nhật sản phẩm thành công!'});

    } catch (error) {
        console.error('[PUT Product Error]:', error);
        res.status(500).json({error: 'Lỗi máy chủ nội bộ.'});
    }
});

// 4. Xóa sản phẩm (đăng nhập + admin)
app.delete('/api/products/:id', authenticateToken, isAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await pool.execute('DELETE FROM Product WHERE ProductID=?', [id]);
        
        if (result.affectedRows === 0) {
            return res.status(404).json({error: 'Không tìm thấy sản phẩm.'});
        }

        res.status(200).json({message: 'Đã xóa sản phẩm thành công!'});

    } catch (error) {
        console.error('[DELETE Product Error]:', error);

        // Lỗi sản phẩm đang dính trong đơn hàng
        if (error.code === 'ER_ROW_IS_REFERENCED_2') {
            return res.status(409).json({error: 'Không thể xóa! Sản phẩm này đã có khách đặt mua, hãy thử chuyển Trạng thái sang "Ngừng bán".'});
        }

        res.status(500).json({error: 'Lỗi máy chủ nội bộ.'});
    }
});

// 5. Lấy chi tiết 1 sản phẩm cụ thể (Dùng cho product-detail)
app.get('/api/products/:id', async (req, res) => {
    try {
        const sql = `
            SELECT p.*, c.CategoryName 
            FROM Product p 
            LEFT JOIN Category c ON p.CategoryID = c.CategoryID
            WHERE p.ProductID = ?
        `;
        const [products] = await pool.execute(sql, [req.params.id]);
        
        if (products.length === 0) {
            return res.status(404).json({ error: 'Không tìm thấy sản phẩm này!' });
        }
        // Trả về đúng 1 cái bánh đầu tiên tìm được
        res.json(products[0]); 
    } catch (error) {
        res.status(500).json({ error: 'Lỗi khi lấy chi tiết sản phẩm' });
    }
});

// -- API tạo nhân viên -- (XXX)
app.post('/api/admin/employees', authenticateToken, isAdmin, async (req, res) => {
    const {username, password, fullName, position, hireDate} = req.body;

    if (!username || !password || !fullName || !position) {
        return res.status(400).json({ error: 'Vui lòng nhập đầy đủ thông tin bắt buộc.' });
    }

    // Mật khẩu cho nhân viên yêu cầu độ dài tối thiểu
    if (password.length < 6) {
        return res.status(400).json({error: 'Mật khẩu phải có ít nhất 6 ký tự.'});
    }

    // Dữ liệu chuẩn rồi mới xin kết nối Database
    const connection = await pool.getConnection();

    try {
        await connection.beginTransaction(); // Đảm bảo tất cả lệnh thành công, nếu ko thì hủy hết

        const hashedPassword = await bcrypt.hash(password, 10);
        const roleId = 3; // nhân viên

        // Bước 1: Thêm vào bảng User
        const sqlUser = 'INSERT INTO User (Username, Password, FullName, RoleID) VALUES (?, ?, ?, ?)';
        const [userResult] = await connection.execute(sqlUser, [username, hashedPassword, fullName, roleId]);
        
        const newUserId = userResult.insertId;

        // Bước 2: Liên kết sang bảng Employee
        const sqlEmployee = 'INSERT INTO Employee (UserID, Position, HireDate) VALUES (?, ?, ?)';
        const effectiveHireDate = hireDate || new Date().toISOString().split('T')[0]; // Mặc định là ngày hôm nay nếu không nhập
        
        await connection.execute(sqlEmployee, [newUserId, position, effectiveHireDate]);

        // Bước 3: Xác nhận lưu toàn bộ
        await connection.commit(); // Kết thúc vùng "Đảm bảo tất cả lệnh thành công, nếu ko thì hủy hết"
        res.status(201).json({message: 'Tạo hồ sơ nhân viên thành công!', employeeId: newUserId});

    } catch (error) {
        await connection.rollback();
        console.error('[Create Employee Error]:', error);

        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({error: 'Tên tài khoản (Username) này đã tồn tại trong hệ thống.'});
        }

        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });

    } finally {
        connection.release();
    }
});


// --- API cho profile ---
// 1. Xem thông tin hồ sơ (XXX)
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; 

        const sql = 'SELECT UserID, Username, FullName, Phone, Email, RoleID FROM User WHERE UserID = ?';
        const [users] = await pool.execute(sql, [userId]);
        
        if (users.length === 0) {
            return res.status(404).json({ error: 'Không tìm thấy hồ sơ người dùng!' });
        }
        
        res.status(200).json({
            message: 'Lấy thông tin thành công',
            profile: users[0]
        });
    } catch (error) {
        console.error('[GET Profile Error]:', error);
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ khi lấy thông tin cá nhân.' });
    }
});

// 2. Cập nhật thông tin hồ sơ (XXX)
app.put('/api/profile', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; 
        const { FullName, Phone, Email } = req.body;

        // Kiểm tra dữ liệu đầu vào
        if (!FullName || FullName.trim() === '' || !Email || Email.trim() === '') {
            return res.status(400).json({ error: 'Họ tên và Email không được để trống.' });
        }

        // Thực hiện cập nhật
        const sql = 'UPDATE User SET FullName = ?, Phone = ?, Email = ? WHERE UserID = ?';
        const [result] = await pool.execute(sql, [FullName.trim(), Phone || null, Email.trim(), userId]);
        
        // Kiểm tra xem có thực sự sửa được dòng nào không
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: 'Không tìm thấy tài khoản để cập nhật.' });
        }
        
        res.status(200).json({ message: 'Cập nhật hồ sơ cá nhân thành công!' });

    } catch (error) {
        console.error('[PUT Profile Error]:', error);
        
        // Bắt lỗi nếu khách nhập Email trùng với người khác
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email này đã được sử dụng bởi tài khoản khác.' });
        }

        res.status(500).json({ error: 'Lỗi máy chủ nội bộ khi cập nhật thông tin.' });
    }
});

// -- Mở server --
const PORT = process.env.PORT || 3000; 

app.listen(PORT, function() {
    // Khi bắt đầu nghe thành công, chạy dòng chữ thông báo
    console.log(`Server đang chạy trên port ${PORT}`); // "`" và "${}" dùng thay cho ghép chữ bằng "+"
});
