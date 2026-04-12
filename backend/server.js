require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
// Mỗi khi có request thì phải đi qua trạm gac use()
app.use(cors()); // Chạm gác đầu tiên cors() kiểm tra
app.use(express.json()); /* Chạm thứ 2 kiểm tra xem dl gửi lên có phải json ko và nếu đúng 
chuyển thành object để mình đọc được */

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

// -- API đăng kí tài khoản --
app.post('/api/register', async(req, res) => {
    try{
        const {username, password, fullName, phone, email} = req.body; //const {...} để ko phải nhập nhiều lần. VD: const username = req.body; const password = req.body; ...

        if(!username || !password || !email){
            return res.status(400).json({ error: 'Vui lòng nhập đủ các trường bắt buộc (username, password, email).' });
        }

        // Băm mật khẩu
        const hashedPassword = await bcrypt.hash(password, 10);
        const roleID = 1; // Customer

        // Cho vào database
        const sql = 'INSERT INTO User (Username, Password, FullName, Phone, Email, RoleID) VALUES (?, ?, ?, ?, ?, ?)'; // Ngăn sql coi các thành phần thành câu lệnh
        const [result] = await pool.execute(sql, [username, hashedPassword, fullName, phone, email, roleID]); // Vì mysql12 gửi về 2 phần tử nên dùng [result] vì chỉ cần phẩn tử đầu tiên ([,result] để lấy phần tử thú 2)

        res.status(201).json({
            message: 'Đăng kí tài khoản thành công.',
            userID: result.insertId
        });
    }
    catch(error){
        console.error('[Register API Error]:', error);
        
        // Lỗi trùng lặp dữ liệu của MySQL 
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Username hoặc Email đã tồn tại trong hệ thống.' });
        }

        // Lỗi không lường trước được
        res.status(500).json({ error: 'Lỗi máy chủ nội bộ. Vui lòng thử lại sau.' });
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

// -- Mở server --
const PORT = process.env.PORT || 3000; 

app.listen(PORT, function() {
    // Khi bắt đầu nghe thành công, chạy dòng chữ thông báo
    console.log(`Server đang chạy trên port ${PORT}`); // "`" và "${}" dùng thay cho ghép chữ bằng "+"
});
