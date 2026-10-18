const express = require("express");
const session = require("express-session");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const dotenv = require("dotenv");
const path = require("path");

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ==============================
// DATABASE
// ==============================

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
    db.run(`
        CREATE TABLE IF NOT EXISTS siswa (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nama TEXT NOT NULL,
            nisn TEXT NOT NULL UNIQUE,
            kelas TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    `);
});

// ==============================
// MIDDLEWARE
// ==============================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: false,
            maxAge: 1000 * 60 * 60 * 2
        }
    })
);

app.use(express.static(path.join(__dirname, "public")));

// ==============================
// ADMIN CHECK
// ==============================

function requireAdmin(req, res, next) {
    if (!req.session.admin) {
        return res.status(401).json({
            success: false,
            message: "Akses admin diperlukan."
        });
    }

    next();
}

// ==============================
// LOGIN ADMIN
// ==============================

app.post("/api/login", async (req, res) => {

    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            success: false,
            message: "Username dan password wajib diisi."
        });
    }

    const validUsername =
        username === process.env.ADMIN_USERNAME;

    const validPassword =
        await bcrypt.compare(
            password,
            await bcrypt.hash(process.env.ADMIN_PASSWORD, 10)
        );

    if (!validUsername || !validPassword) {
        return res.status(401).json({
            success: false,
            message: "Username atau password salah."
        });
    }

    req.session.admin = true;

    res.json({
        success: true,
        message: "Login berhasil."
    });
});

// ==============================
// LOGOUT
// ==============================

app.post("/api/logout", requireAdmin, (req, res) => {

    req.session.destroy(() => {

        res.json({
            success: true,
            message: "Logout berhasil."
        });

    });

});

// ==============================
// CEK LOGIN
// ==============================

app.get("/api/me", (req, res) => {

    res.json({
        admin: !!req.session.admin
    });

});

// ==============================
// DATA PUBLIK
// NISN DISAMARKAN
// ==============================

app.get("/api/siswa", (req, res) => {

    db.all(
        `
        SELECT id, nama, nisn, kelas
        FROM siswa
        ORDER BY nama ASC
        `,
        [],
        (err, rows) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Gagal mengambil data."
                });
            }

            const data = rows.map(siswa => {

                const nisn = siswa.nisn;

                return {
                    id: siswa.id,
                    nama: siswa.nama,
                    nisn:
                        "*".repeat(
                            Math.max(0, nisn.length - 4)
                        ) + nisn.slice(-4),
                    kelas: siswa.kelas
                };

            });

            res.json(data);
        }
    );

});

// ==============================
// DATA ADMIN
// NISN LENGKAP
// ==============================

app.get("/api/admin/siswa", requireAdmin, (req, res) => {

    db.all(
        `
        SELECT id, nama, nisn, kelas
        FROM siswa
        ORDER BY nama ASC
        `,
        [],
        (err, rows) => {

            if (err) {
                return res.status(500).json({
                    success: false,
                    message: "Gagal mengambil data."
                });
            }

            res.json(rows);
        }
    );

});

// ==============================
// TAMBAH SISWA
// ==============================

app.post("/api/admin/siswa", requireAdmin, (req, res) => {

    const { nama, nisn, kelas } = req.body;

    if (!nama || !nisn || !kelas) {
        return res.status(400).json({
            success: false,
            message: "Semua data wajib diisi."
        });
    }

    if (!/^\d{10}$/.test(nisn)) {
        return res.status(400).json({
            success: false,
            message: "NISN harus terdiri dari 10 angka."
        });
    }

    db.run(
        `
        INSERT INTO siswa
        (nama, nisn, kelas)
        VALUES (?, ?, ?)
        `,
        [nama.trim(), nisn.trim(), kelas.trim()],
        function (err) {

            if (err) {

                if (err.message.includes("UNIQUE")) {
                    return res.status(400).json({
                        success: false,
                        message: "NISN tersebut sudah terdaftar."
                    });
                }

                return res.status(500).json({
                    success: false,
                    message: "Gagal menyimpan data."
                });
            }

            res.json({
                success: true,
                message: "Data siswa berhasil ditambahkan.",
                id: this.lastID
            });

        }
    );

});

// ==============================
// EDIT SISWA
// ==============================

app.put("/api/admin/siswa/:id", requireAdmin, (req, res) => {

    const { nama, nisn, kelas } = req.body;
    const id = req.params.id;

    if (!nama || !nisn || !kelas) {
        return res.status(400).json({
            success: false,
            message: "Semua data wajib diisi."
        });
    }

    if (!/^\d{10}$/.test(nisn)) {
        return res.status(400).json({
            success: false,
            message: "NISN harus terdiri dari 10 angka."
        });
    }

    db.run(
        `
        UPDATE siswa
        SET nama = ?, nisn = ?, kelas = ?
        WHERE id = ?
        `,
        [
            nama.trim(),
            nisn.trim(),
            kelas.trim(),
            id
        ],
        function (err) {

            if (err) {

                if (err.message.includes("UNIQUE")) {
                    return res.status(400).json({
                        success: false,
                        message: "NISN tersebut sudah digunakan."
                    });
                }

                return res.status(500).json({
                    success: false,
                    message: "Gagal mengubah data."
                });
            }

            res.json({
                success: true,
                message: "Data berhasil diubah."
            });

        }
    );

});

// ==============================
// HAPUS SISWA
// ==============================

app.delete(
    "/api/admin/siswa/:id",
    requireAdmin,
    (req, res) => {

        db.run(
            `
            DELETE FROM siswa
            WHERE id = ?
            `,
            [req.params.id],
            function (err) {

                if (err) {
                    return res.status(500).json({
                        success: false,
                        message: "Gagal menghapus data."
                    });
                }

                res.json({
                    success: true,
                    message: "Data berhasil dihapus."
                });

            }
        );

    }
);

// ==============================
// SERVER
// ==============================

app.listen(PORT, "0.0.0.0", () => {

    console.log("");
    console.log("==========================================");
    console.log(" ADEM SMKN 1 KRAGILAN");
    console.log("==========================================");
    console.log(
        `Website: http://localhost:${PORT}`
    );
    console.log(
        `Admin:   http://localhost:${PORT}/admin.html`
    );
    console.log("==========================================");

});