const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const dotenv = require("dotenv");
const multer = require("multer");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");

// 환경 변수 설정
dotenv.config();

const app = express();

// 미들웨어 설정
app.use(express.json());
app.use(
  cors({
    origin: ["http://127.0.0.1:5500"],
    credentials: true,
  })
);

// 정적 파일 제공 설정
app.use("/uploads", express.static("uploads"));

// API 라우트들을 여기에 배치
// 회원가입
app.post("/api/auth/register", async (req, res) => {
  try {
    const { studentId, name, password } = req.body;

    // 학번 형식 검증
    if (!/^\d{4}$/.test(studentId)) {
      return res.status(400).json({ message: "학번은 4자리 숫자여야 합니다." });
    }

    // 이름 길이 검증
    if (name.length < 2 || name.length > 10) {
      return res
        .status(400)
        .json({ message: "이름은 2자에서 10자 사이여야 합니다." });
    }

    // 비밀번호 길이 검증
    if (password.length < 8) {
      return res
        .status(400)
        .json({ message: "비밀번호는 8자 이상이어야 합니다." });
    }

    const existingUser = await User.findOne({ studentId });
    if (existingUser) {
      return res.status(400).json({ message: "이미 등록된 학번입니다." });
    }

    const user = new User({ studentId, name, password });
    await user.save();

    res.status(201).json({ message: "회원가입이 완료되었습니다." });
  } catch (err) {
    console.error("회원가입 오류:", err);
    if (err.code === 11000) {
      return res.status(400).json({
        message: "이미 등록된 학번입니다.",
      });
    }
    res.status(500).json({
      message: "회원가입 처리 중 오류가 발생했습니다.",
      error: err.message,
    });
  }
});

// 로그인 API 수정
app.post("/api/auth/login", async (req, res) => {
  try {
    const { studentId, password } = req.body;

    const user = await User.findOne({ studentId });
    if (!user) {
      return res.status(401).json({
        message: "학번 또는 비밀번호가 잘못되었습니다.",
      });
    }

    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({
        message: "학번 또는 비밀번호가 잘못되었습니다.",
      });
    }

    // 토큰 생성 시 _id를 문자열로 변환
    const { accessToken, refreshToken } = generateTokens({
      _id: user._id.toString(),
      role: user.role,
    });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await RefreshToken.create({
      userId: user._id,
      token: refreshToken,
      expiresAt,
    });

    res.json({
      accessToken,
      refreshToken,
      role: user.role,
      expiresIn: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN),
    });
  } catch (err) {
    console.error("로그인 오류:", err);
    res.status(500).json({
      message: "로그인 처리 중 오류가 발생했습니다.",
    });
  }
});

// 메인 페이지 처리를 API 상태 확인 응답으로 변경
app.get("/", (req, res) => {
  res.json({ message: "환경지킴이 API 서버가 실행중입니다." });
});

// uploads 디렉토리 생성 함수
function createUploadsDirectory() {
  const uploadsDir = path.join(__dirname, "uploads");
  if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir);
    console.log("uploads 디렉토리가 생성되었습니다.");
  }
}

// MongoDB 연결 및 서버 시작
mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/eco-guardian")
  .then(() => {
    console.log("MongoDB 연결 성공");

    // uploads 디렉토리 생성
    createUploadsDirectory();

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
      console.log(`서버가 포트 ${PORT}에서 실행중입니다.`);
    });

    return initializeCategories();
  })
  .catch((err) => console.error("MongoDB 연결 실패:", err));

// 파일 업로드 설정
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(
      null,
      `${Date.now()}-${Math.random().toString(36).substring(7)}${path.extname(
        file.originalname
      )}`
    );
  },
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(
      path.extname(file.originalname).toLowerCase()
    );
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error("이미지 파일만 업로드 가능합니다."));
  },
});

// MongoDB 스키마 정의
const userSchema = new mongoose.Schema({
  studentId: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    validate: {
      validator: function (v) {
        return /^\d{4}$/.test(v); // 4자리 숫자만 허용
      },
      message: "학번은 4자리 숫자여야 합니다.",
    },
  },
  name: {
    type: String,
    required: true,
    trim: true,
    minlength: [2, "이름은 최소 2자 이상이어야 합니다."],
    maxlength: [10, "이름은 최대 10자까지 가능합니다."],
  },
  password: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// 비밀번호 해싱
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// 비밀번호 검증 메소드
userSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model("User", userSchema);

// 카테고리 스키마 추가
const categorySchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    trim: true,
  },
  name: {
    type: String,
    required: true,
    trim: true,
  },
  description: {
    type: String,
    required: true,
  },
  points: {
    type: Number,
    default: 1,
  },
  isActive: {
    type: Boolean,
    default: true,
  },
  order: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Category = mongoose.model("Category", categorySchema);

// 활동 스키마 수정
const activitySchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  category: {
    type: String,
    required: true,
  },
  imageUrl: {
    type: String,
    required: true,
  },
  status: {
    type: String,
    enum: ["pending", "approved", "rejected"],
    default: "pending",
  },
  description: {
    type: String,
    maxLength: 500,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  approvedAt: Date,
  approvedBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  dailyLimit: {
    type: Number,
    default: 1, // 각 카테고리별 하루 최대 1회
  },
});

// 진행률 계산 메소드
activitySchema.statics.calculateProgress = async function () {
  const approvedCount = await this.countDocuments({ status: "approved" });
  const progressPercent = Math.floor(approvedCount / 3); // 3개당 1%
  return {
    percent: Math.min(progressPercent, 100),
    totalApproved: approvedCount,
    remainingForNext: 3 - (approvedCount % 3),
  };
};

const Activity = mongoose.model("Activity", activitySchema);

// JWT 검증 미들웨어 수정
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "인증 토큰이 필요합니다." });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({
          message: "토큰이 만료되었습니다.",
          code: "TOKEN_EXPIRED",
        });
      }
      return res.status(403).json({ message: "유효하지 않은 토큰입니다." });
    }

    req.user = decoded;
    next();
  });
};

// 관리자 권한 확인 미들웨어
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (user.role !== "admin") {
      return res.status(403).json({ message: "관리자 권한이 필요합니다." });
    }
    next();
  } catch (err) {
    res.status(500).json({ message: "서버 오류", error: err.message });
  }
};

// 팁 스키마 수정 - 이미지 URL과 상세 내용 추가
const tipSchema = new mongoose.Schema({
  category: {
    type: String,
    enum: ["탄소중립", "식물관리"],
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  imageUrl: String,
  details: [
    {
      subtitle: String,
      description: String,
    },
  ],
  order: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
  updatedAt: {
    type: Date,
    default: Date.now,
  },
});

const Tip = mongoose.model("Tip", tipSchema);

// API 라우트
// 기본 라우트
app.get("/", (req, res) => {
  res.json({ message: "환경지킴이 API 서버가 실행중입니다." });
});

// 토큰 갱신 API
app.post("/api/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({ message: "리프레시 토큰이 필요합니다." });
    }

    // 저장된 리프레시 토큰 확인
    const savedToken = await RefreshToken.findOne({ token: refreshToken });
    if (!savedToken) {
      return res
        .status(401)
        .json({ message: "유효하지 않은 리프레시 토큰입니다." });
    }

    // 토큰 증
    const decoded = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      await RefreshToken.deleteOne({ token: refreshToken });
      return res.status(401).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 새로운 토큰 발급
    const { accessToken: newAccessToken, refreshToken: newRefreshToken } =
      generateTokens(user);

    // 기존 리프레시 토큰 삭제 후 새로운 토큰 저장
    await RefreshToken.deleteOne({ token: refreshToken });

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    await RefreshToken.create({
      userId: user._id,
      token: newRefreshToken,
      expiresAt,
    });

    res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
      expiresIn: parseInt(process.env.ACCESS_TOKEN_EXPIRES_IN),
    });
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      return res.status(401).json({ message: "유효하지 않은 토큰입니다." });
    }
    if (err.name === "TokenExpiredError") {
      return res.status(401).json({ message: "만료된 토큰 입니다." });
    }
    res.status(500).json({ message: "토큰 갱신 실패", error: err.message });
  }
});

// 로그아웃 API 수정
app.post("/api/auth/logout", authenticateToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;

    // refreshToken이 있는 경우에만 삭제 시도
    if (refreshToken) {
      await RefreshToken.deleteOne({ token: refreshToken });
    }

    // 성공 응답 반환
    res.status(200).json({ message: "로그아웃되었습니다." });
  } catch (err) {
    console.error("로그아웃 오류:", err);
    // 오류가 발생해도 클라이언트에서는 로그아웃 처리를 진행할 수 있도록 200 응답
    res.status(200).json({ message: "로그아웃되었습니다." });
  }
});

// 이미지 업로드 API 수정
app.post(
  "/api/upload",
  authenticateToken,
  upload.single("image"),
  (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({ message: "이미지를 선택해주세요." });
      }

      // 이미지 URL 생성
      const imageUrl = `${req.protocol}://${req.get("host")}/uploads/${
        req.file.filename
      }`;

      res.json({
        imageUrl,
        message: "이미지가 성공적으로 업로드되었습니다.",
      });
    } catch (err) {
      console.error("이미지 업로드 오류:", err);
      res.status(500).json({
        message: "이미지 업로드 중 오류가 발생했습니다.",
        error: err.message,
      });
    }
  }
);

// 활동 목록 조회
app.get("/api/activities", async (req, res) => {
  try {
    const { page = 1, limit = 10, status, category } = req.query;
    const skip = (page - 1) * limit;

    const filter = {};
    if (status) filter.status = status;
    if (category) filter.category = category;

    const activities = await Activity.find(filter)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .select("-userId");

    const total = await Activity.countDocuments(filter);

    res.json({
      activities,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / limit),
      totalItems: total,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "활동 목록 조회 실패", error: err.message });
  }
});

// 활동 등록 전 검증 미들웨어
const validateActivity = async (req, res, next) => {
  try {
    const { category } = req.body;
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // 오늘 해당 카테고리에 등록한 활동 수 확인
    const todayActivities = await Activity.countDocuments({
      userId: req.user.id,
      category,
      createdAt: { $gte: today },
    });

    if (todayActivities >= 1) {
      return res.status(400).json({
        message: "이 카테고리는 하루에 한 번만 인증할 수 있습니다.",
        nextAvailable: new Date(today.getTime() + 24 * 60 * 60 * 1000),
      });
    }

    next();
  } catch (err) {
    res.status(500).json({ message: "활동 검증 실패", error: err.message });
  }
};

// 활동 등록 API 수정
app.post(
  "/api/activities",
  [authenticateToken, validateActivity],
  async (req, res) => {
    try {
      const { category, imageUrl, description } = req.body;

      // 필수 필드 검증
      if (!category || !imageUrl) {
        return res.status(400).json({
          message: "카테고리와 이미지는 필수 항목입니다.",
        });
      }

      // 카테고리 유효성 검사
      const validCategory = await Category.findOne({
        code: category,
        isActive: true,
      });

      if (!validCategory) {
        return res.status(400).json({
          message: "올바르지 않은 카테고리입니다.",
        });
      }

      // 활동 생성
      const activity = new Activity({
        userId: req.user.id,
        category: validCategory.code,
        imageUrl,
        description: description || "",
        status: "pending",
      });

      await activity.save();

      // 현재 진행률 계산
      const progress = await Activity.calculateProgress();

      // 사용자 개인 진행률 계산
      const userProgress = await Activity.countDocuments({
        userId: req.user.id,
        status: "approved",
      });

      res.status(201).json({
        message: "활동이 등록되었습니다. 관리자 승인 후 반영됩니다.",
        activity: {
          id: activity._id,
          category: validCategory.name,
          status: "pending",
          createdAt: activity.createdAt,
        },
        progress,
        userProgress: {
          total: userProgress,
          message: `지금까지 ${userProgress}개의 활동을 인증했습니다.`,
        },
      });
    } catch (err) {
      console.error("활동 등록 오류:", err);
      res.status(500).json({
        message: "활동 등록 중 오류가 발생했습니다.",
        error: err.message,
      });
    }
  }
);

// 알림 스키마 정의
const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  type: {
    type: String,
    enum: [
      "activity_approved",
      "activity_rejected",
      "goal_achieved",
      "daily_reminder",
    ],
    required: true,
  },
  title: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  read: {
    type: Boolean,
    default: false,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const Notification = mongoose.model("Notification", notificationSchema);

// 사용자 통계 스키마 정의
const userStatsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  categoryStats: [
    {
      category: String,
      approved: Number,
      rejected: Number,
      pending: Number,
    },
  ],
  totalApproved: Number,
  lastActivityDate: Date,
  streak: Number, // 연속 참여일
  updatedAt: Date,
});

const UserStats = mongoose.model("UserStats", userStatsSchema);

// 알림 생성 함수
async function createNotification(userId, type, title, message) {
  try {
    const notification = new Notification({
      userId,
      type,
      title,
      message,
    });
    await notification.save();
    return notification;
  } catch (err) {
    console.error("알림 생성 실패:", err);
    return null;
  }
}

// 사용자 통계 업데이트 함수
async function updateUserStats(userId, category, status) {
  try {
    let stats = await UserStats.findOne({ userId });

    if (!stats) {
      stats = new UserStats({
        userId,
        categoryStats: [],
        totalApproved: 0,
        streak: 0,
      });
    }

    // 카테고리별 통계 업데이트
    let categoryStats = stats.categoryStats.find(
      (s) => s.category === category
    );
    if (!categoryStats) {
      categoryStats = {
        category,
        approved: 0,
        rejected: 0,
        pending: 0,
      };
      stats.categoryStats.push(categoryStats);
    }

    // 이전 상태의 카운트 감소
    if (status === "approved") {
      categoryStats.pending--;
      categoryStats.approved++;
      stats.totalApproved++;
    } else if (status === "rejected") {
      categoryStats.pending--;
      categoryStats.rejected++;
    } else {
      categoryStats.pending++;
    }

    // 연속 참여일 업데이트
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    if (status === "approved") {
      if (stats.lastActivityDate) {
        const lastDate = new Date(stats.lastActivityDate);
        lastDate.setHours(0, 0, 0, 0);

        const diffDays = Math.floor((today - lastDate) / (1000 * 60 * 60 * 24));

        if (diffDays === 1) {
          stats.streak++;
        } else if (diffDays > 1) {
          stats.streak = 1;
        }
      } else {
        stats.streak = 1;
      }
      stats.lastActivityDate = today;
    }

    stats.updatedAt = new Date();
    await stats.save();

    return stats;
  } catch (err) {
    console.error("사용자 통계 업데이트 실패:", err);
    return null;
  }
}

// 활동 승인/거절 API 수정
app.patch(
  "/api/activities/:id/status",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!["approved", "rejected"].includes(status)) {
        return res.status(400).json({ message: "잘못된 상태값입니다." });
      }

      const activity = await Activity.findById(id);
      if (!activity) {
        return res.status(404).json({ message: "활동을 찾을 수 없습니다." });
      }

      // 상태 업데이트
      activity.status = status;
      activity.approvedAt = status === "approved" ? new Date() : null;
      activity.approvedBy = status === "approved" ? req.user.id : null;
      await activity.save();

      // 사용자 통계 업데이트
      await updateUserStats(activity.userId, activity.category, status);

      // 알림 생성
      let notificationTitle, notificationMessage;
      if (status === "approved") {
        notificationTitle = "활동 승인";
        notificationMessage = "회원님의 환경 보호 활동이 승인되었습니다!";
      } else {
        notificationTitle = "활동 거절";
        notificationMessage =
          "회원님의 활동이 기준에 맞지 않아 승인되지 았습니다.";
      }

      await createNotification(
        activity.userId,
        `activity_${status}`,
        notificationTitle,
        notificationMessage
      );

      // 전체 진행률 확인 및 목표 달성 알림
      const progress = await Activity.calculateProgress();
      if (progress.percent >= 100) {
        await createNotification(
          activity.userId,
          "goal_achieved",
          "목표 달성!",
          "축하합니다! 리 학교에 나무를 심을 수 있게 되었습니다."
        );
      }

      // 관리자 활동 로깅
      await logAdminAction(
        req.user.id,
        status === "approved" ? "approve_activity" : "reject_activity",
        {
          activityId: id,
          category: activity.category,
          userId: activity.userId,
        }
      );

      res.json({
        activity,
        progress,
        message: `활동이 ${status === "approved" ? "승인" : "거절"}되었습니다.`,
      });
    } catch (err) {
      res
        .status(400)
        .json({ message: "상태 업데이트 실패", error: err.message });
    }
  }
);

// 진행률 조회 API
app.get("/api/progress", authenticateToken, async (req, res) => {
  try {
    // 전체 진행률 계산
    const progress = await Activity.calculateProgress();

    // 사용자별 진행률 계산
    const userProgress = await Activity.countDocuments({
      userId: req.user.id,
      status: "approved",
    });

    // 오늘 승인된 활동 수 계산
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const todayApproved = await Activity.countDocuments({
      userId: req.user.id,
      status: "approved",
      createdAt: { $gte: today },
    });

    res.json({
      percent: progress.percent,
      totalApproved: progress.totalApproved,
      remainingForNext: progress.remainingForNext,
      userContribution: {
        total: userProgress,
        today: todayApproved,
        percent:
          progress.totalApproved > 0
            ? ((userProgress / progress.totalApproved) * 100).toFixed(1)
            : "0",
      },
    });
  } catch (err) {
    console.error("진행률 조회 오류:", err);
    res.status(500).json({
      message: "진행률을 조회하는 중 오류가 발생했습니다.",
    });
  }
});

// 알림 조회 API
app.get("/api/notifications", authenticateToken, async (req, res) => {
  try {
    const notifications = await Notification.find({
      userId: req.user.id,
      read: false,
    })
      .sort({ createdAt: -1 })
      .limit(10);

    const unreadCount = await Notification.countDocuments({
      userId: req.user.id,
      read: false,
    });

    res.json({
      notifications,
      unreadCount,
      hasMore: notifications.length === 10,
    });
  } catch (err) {
    console.error("알림 조회 오류:", err);
    res.status(500).json({
      message: "알림을 조회하는 중 오류가 발생했습니다.",
    });
  }
});

// 카테고리 목록 조회
app.get("/api/categories", async (req, res) => {
  try {
    const categories = await Category.find({ isActive: true }).sort({
      order: 1,
      createdAt: -1,
    });
    res.json(categories);
  } catch (err) {
    res
      .status(500)
      .json({ message: "카테고리 목록 조회 실패", error: err.message });
  }
});

// 카테고리 추가 (관리자 전용)
app.post("/api/categories", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { code, name, description, points, order } = req.body;

    const existingCategory = await Category.findOne({ code });
    if (existingCategory) {
      return res
        .status(400)
        .json({ message: "이미 존재하는 카테고리 코드입니다." });
    }

    const category = new Category({
      code,
      name,
      description,
      points: points || 1,
      order: order || 0,
    });

    await category.save();
    res.status(201).json(category);
  } catch (err) {
    res.status(400).json({ message: "카테고리 추가 실패", error: err.message });
  }
});

// 카테고리 수정 (관리자 전용)
app.put(
  "/api/categories/:code",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { code } = req.params;
      const { name, description, points, order, isActive } = req.body;

      const category = await Category.findOneAndUpdate(
        { code },
        {
          name,
          description,
          points,
          order,
          isActive,
          updatedAt: new Date(),
        },
        { new: true }
      );

      if (!category) {
        return res.status(404).json({ message: "카테고리 찾을 수 없습니다." });
      }

      res.json(category);
    } catch (err) {
      res
        .status(400)
        .json({ message: "카테고리 수정 실패", error: err.message });
    }
  }
);

// 팁 관리 API 추가
app.get("/api/tips", async (req, res) => {
  try {
    const { category } = req.query;
    const query = category ? { category } : {};

    const tips = await Tip.find(query)
      .sort({ order: 1, createdAt: -1 })
      .select("category title content imageUrl order");

    res.json(tips);
  } catch (err) {
    console.error("팁 조회 오류:", err);
    res.status(500).json({
      message: "팁을 조회하는 중 오류가 발생했습니다.",
    });
  }
});

// 팁 추가
app.post("/api/tips", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { category, title, content, imageUrl, order } = req.body;

    const tip = new Tip({
      category,
      title,
      content,
      imageUrl,
      order: order || 0,
    });

    await tip.save();
    res.status(201).json(tip);
  } catch (err) {
    res.status(400).json({ message: "팁 추가 실패", error: err.message });
  }
});

// 팁 수정
app.put("/api/tips/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { category, title, content, imageUrl, order } = req.body;

    const tip = await Tip.findByIdAndUpdate(
      id,
      {
        category,
        title,
        content,
        imageUrl,
        order,
        updatedAt: new Date(),
      },
      { new: true }
    );

    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }

    res.json(tip);
  } catch (err) {
    res.status(400).json({ message: "팁 수정 실패", error: err.message });
  }
});

// 팁 삭제
app.delete("/api/tips/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const tip = await Tip.findByIdAndDelete(id);

    if (!tip) {
      return res.status(404).json({ message: "팁을 찾을 수 없습니다." });
    }

    res.json({ message: "팁이 삭제되었습니다." });
  } catch (err) {
    res.status(400).json({ message: "팁 삭제 실패", error: err.message });
  }
});

// 카테고리별 팁 조회 API
app.get("/api/tips/:category", async (req, res) => {
  try {
    const { category } = req.params;

    // 카테고리 유효성 검사
    if (!["탄소중립", "식물관리"].includes(category)) {
      return res.status(400).json({
        message: "올바르지 않은 카테고리입니다.",
        validCategories: ["탄소중립", "식물관리"],
      });
    }

    const tips = await Tip.find({
      category,
      isActive: true,
    })
      .sort({ order: 1 })
      .select("title content");

    // 팁이 없는 경우 기본 팁 생성
    if (tips.length === 0) {
      const defaultTips =
        category === "탄소중립"
          ? [
              {
                title: "일회용품 줄이기",
                content: "텀블러와 장바구니를 사용해요",
                order: 1,
              },
              {
                title: "전기 절약하기",
                content: "사용하지 않는 전자기기의 플러그를 뽑아요",
                order: 2,
              },
            ]
          : [
              {
                title: "물주기 요령",
                content: "식물의 종류에 따라 적절한 양의 물을 주세요",
                order: 1,
              },
              {
                title: "햇빛 관리",
                content: "식물이 좋아하는 채광 환경을 만들어주세요",
                order: 2,
              },
            ];

      await Tip.insertMany(
        defaultTips.map((tip) => ({
          ...tip,
          category,
          isActive: true,
        }))
      );

      return res.json({ tips: defaultTips });
    }

    res.json({ tips });
  } catch (err) {
    console.error("팁 조회 오류:", err);
    res.status(500).json({
      message: "팁을 조회하는 중 오류가 발생했습니다.",
    });
  }
});

// 초기 카테고리 데이터 설정 함수 수정
async function initializeCategories() {
  try {
    const count = await Category.countDocuments();
    if (count === 0) {
      const defaultCategories = [
        {
          code: "no_leftover",
          name: "잔반없는식사",
          description: "다 먹은 빈 접시나 식판 촬영",
          order: 1,
        },
        {
          code: "public_transport",
          name: "대중교통이용",
          description: "대중교통 이용 혹은 자전거 이용중인 사진 촬영",
          order: 2,
        },
        {
          code: "save_energy",
          name: "에너지절약",
          description: "불끄기 스위치 누르는 사진 촬영",
          order: 3,
        },
      ];

      await Category.insertMany(defaultCategories);
      console.log("기본 카테고리가 생성되었습니다.");
    }
  } catch (err) {
    console.error("카테고리 초기화 실패:", err);
  }
}

// 회원 관리 관련 API 추가
// 회원 목록 조회 (관리자 전용)
app.get("/api/users", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (search) {
      query.studentId = new RegExp(search, "i");
    }

    const users = await User.find(query)
      .select("-password")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments(query);

    res.json({
      users,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / limit),
      totalUsers: total,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "회원 목록 조회 실패", error: err.message });
  }
});

// 회원 상세 정보 조회 (관리자 전용)
app.get("/api/users/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password");
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 사용자의 활동 통계 조회
    const stats = await UserStats.findOne({ userId: user._id });

    // 사용자의 최근 활동 내역
    const recentActivities = await Activity.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      user,
      stats,
      recentActivities,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "회원 정보 조회 실패", error: err.message });
  }
});

// 회원 권한 수정 (관리자 전용)
app.patch(
  "/api/users/:id/role",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { role } = req.body;

      if (!["user", "admin"].includes(role)) {
        return res.status(400).json({ message: "올바르지 않은 권한입니다." });
      }

      const user = await User.findByIdAndUpdate(
        id,
        { role },
        { new: true }
      ).select("-password");

      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }

      res.json({
        message: "사용자 권한이 수정되었습니다.",
        user,
      });
    } catch (err) {
      res.status(400).json({ message: "권한 수정 실패", error: err.message });
    }
  }
);

// 관리자 대시보드 통계 API 수정
app.get(
  "/api/admin/dashboard",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      // 전체 진행률 계산
      const totalApprovedActivities = await Activity.countDocuments({
        status: "approved",
      });
      const progress = Math.min(Math.floor(totalApprovedActivities / 3), 100); // 3개당 1%

      const stats = {
        totalUsers: await User.countDocuments(),
        newUsersToday: await User.countDocuments({
          createdAt: { $gte: today },
        }),
        pendingActivities: await Activity.countDocuments({ status: "pending" }),
        totalApprovedActivities,
        todayActivities: await Activity.countDocuments({
          createdAt: { $gte: today },
        }),
        progress, // 진행률 추가
        categoryStats: [],
      };

      // 카테고리별 통계
      const categories = await Category.find({ isActive: true });
      for (const category of categories) {
        const categoryStats = {
          name: category.name,
          code: category.code,
          approved: await Activity.countDocuments({
            category: category.code,
            status: "approved",
          }),
          pending: await Activity.countDocuments({
            category: category.code,
            status: "pending",
          }),
          rejected: await Activity.countDocuments({
            category: category.code,
            status: "rejected",
          }),
          todaySubmissions: await Activity.countDocuments({
            category: category.code,
            createdAt: { $gte: today },
          }),
        };
        stats.categoryStats.push(categoryStats);
      }

      // 주간 통
      const weekAgo = new Date(today);
      weekAgo.setDate(weekAgo.getDate() - 7);

      stats.weeklyStats = {
        newUsers: await User.countDocuments({
          createdAt: { $gte: weekAgo },
        }),
        approvedActivities: await Activity.countDocuments({
          status: "approved",
          createdAt: { $gte: weekAgo },
        }),
        activeUsers: await Activity.distinct("userId", {
          createdAt: { $gte: weekAgo },
        }).then((users) => users.length),
      };

      res.json(stats);
    } catch (err) {
      res
        .status(500)
        .json({ message: "대시보드 통계 조회 실패", error: err.message });
    }
  }
);

// 관리자 활동 로그 스키마
const adminLogSchema = new mongoose.Schema({
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  action: {
    type: String,
    enum: [
      "approve_activity",
      "reject_activity",
      "modify_category",
      "modify_user",
      "add_tip",
      "delete_category",
      "reset_password",
      "delete_user",
    ],
    required: true,
  },
  details: mongoose.Schema.Types.Mixed,
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const AdminLog = mongoose.model("AdminLog", adminLogSchema);

// 관리자 동 로깅 함수
async function logAdminAction(adminId, action, details) {
  try {
    const log = new AdminLog({
      adminId,
      action,
      details,
    });
    await log.save();
  } catch (err) {
    console.error("관리자 활동 로깅 실패:", err);
  }
}

// 관리자 활동 로그 조회 API
app.get("/api/admin/logs", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 20, action } = req.query;
    const skip = (page - 1) * limit;

    let query = {};
    if (action) {
      query.action = action;
    }

    const logs = await AdminLog.find(query)
      .populate("adminId", "email")
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await AdminLog.countDocuments(query);

    res.json({
      logs,
      currentPage: parseInt(page),
      totalPages: Math.ceil(total / limit),
      totalLogs: total,
    });
  } catch (err) {
    res
      .status(500)
      .json({ message: "활동 로그 조회 실패", error: err.message });
  }
});

// 관리자 설정 스키마
const adminSettingsSchema = new mongoose.Schema({
  adminId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
    unique: true,
  },
  emailNotifications: {
    enabled: {
      type: Boolean,
      default: true,
    },
    types: [
      {
        type: String,
        enum: ["new_activity", "user_report", "goal_reached"],
      },
    ],
  },
  autoApproval: {
    enabled: {
      type: Boolean,
      default: false,
    },
    conditions: {
      userMinApproved: {
        type: Number,
        default: 5,
      },
      categoryLimit: {
        type: Number,
        default: 1,
      },
    },
  },
  dashboardSettings: {
    defaultView: {
      type: String,
      enum: ["overview", "activities", "users"],
      default: "overview",
    },
    refreshInterval: {
      type: Number,
      default: 300000, // 5분
    },
  },
});

const AdminSettings = mongoose.model("AdminSettings", adminSettingsSchema);

// 관리자 설정 조회 API
app.get("/api/admin/settings", authenticateToken, isAdmin, async (req, res) => {
  try {
    let settings = await AdminSettings.findOne({ adminId: req.user.id });
    if (!settings) {
      settings = new AdminSettings({ adminId: req.user.id });
      await settings.save();
    }
    res.json(settings);
  } catch (err) {
    res.status(500).json({ message: "설정 조회 실패", error: err.message });
  }
});

// 관리자 설정 수정 API
app.put("/api/admin/settings", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { emailNotifications, autoApproval, dashboardSettings } = req.body;

    const settings = await AdminSettings.findOneAndUpdate(
      { adminId: req.user.id },
      {
        emailNotifications,
        autoApproval,
        dashboardSettings,
      },
      { new: true, upsert: true }
    );

    // 관리자 활동 로깅
    await logAdminAction(req.user.id, "update_settings", {
      emailNotifications,
      autoApproval,
      dashboardSettings,
    });

    res.json(settings);
  } catch (err) {
    res.status(400).json({ message: "설정 수정 실패", error: err.message });
  }
});

// 사용자 통계 조회 API
app.get("/api/users/stats/me", authenticateToken, async (req, res) => {
  try {
    // 사용자 기본 정보 조회
    const user = await User.findById(req.user.id).select("studentId name");
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 승인된 활동 수 계산
    const totalApproved = await Activity.countDocuments({
      userId: req.user.id,
      status: "approved",
    });

    // 연속 참여일 계산
    const stats = await UserStats.findOne({ userId: req.user.id });

    res.json({
      user: {
        studentId: user.studentId,
        name: user.name,
      },
      personalStats: {
        totalApproved,
        streak: stats?.streak || 0,
      },
    });
  } catch (err) {
    console.error("사용자 통계 조회 오류:", err);
    res.status(500).json({
      message: "통계 조회 중 오류가 발생했습니다.",
      error: err.message,
    });
  }
});

// 알림 읽음 표시 API
app.patch(
  "/api/notifications/:id/read",
  authenticateToken,
  async (req, res) => {
    try {
      const notification = await Notification.findOneAndUpdate(
        { _id: req.params.id, userId: req.user.id },
        { read: true },
        { new: true }
      );

      if (!notification) {
        return res.status(404).json({ message: "알림을 찾을 수 없습니다." });
      }

      res.json(notification);
    } catch (err) {
      res
        .status(400)
        .json({ message: "알림 상태 업데이트 실패", error: err.message });
    }
  }
);

// 모든 알림 읽음 표시 API
app.patch(
  "/api/notifications/read-all",
  authenticateToken,
  async (req, res) => {
    try {
      await Notification.updateMany(
        { userId: req.user.id, read: false },
        { read: true }
      );

      res.json({ message: "모든 알림이 읽음 처리되었습니다." });
    } catch (err) {
      res
        .status(400)
        .json({ message: "알림 상태 업데이트 실패", error: err.message });
    }
  }
);

// 자동 승인 검사 미들웨어
const checkAutoApproval = async (req, res, next) => {
  try {
    const adminSettings = await AdminSettings.findOne({});
    if (!adminSettings?.autoApproval?.enabled) {
      return next();
    }

    const { userMinApproved, categoryLimit } =
      adminSettings.autoApproval.conditions;
    const userId = req.user.id;

    // 사용자의 승인된 활동 수 확인
    const approvedCount = await Activity.countDocuments({
      userId,
      status: "approved",
    });

    if (approvedCount >= userMinApproved) {
      // 오늘 당 카테고리에 확인된 활동 수 확인
      const today = new Date();
      today.setHours(0, 0, 0, 0);

      const todayApprovedCount = await Activity.countDocuments({
        userId,
        category: req.body.category,
        status: "approved",
        createdAt: { $gte: today },
      });

      if (todayApprovedCount < categoryLimit) {
        req.autoApprove = true;
      }
    }

    next();
  } catch (err) {
    console.error("자동 승인 검사 실패:", err);
    next();
  }
};

// 리프레시 토큰 스키마 추가
const refreshTokenSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  token: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: "7d", // MongoDB TTL 인스턴스 사용 기간
  },
});

const RefreshToken = mongoose.model("RefreshToken", refreshTokenSchema);

// 토큰 성 함수
function generateTokens(user) {
  const accessToken = jwt.sign(
    { id: user._id, role: user.role },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN }
  );

  const refreshToken = jwt.sign(
    { id: user._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN }
  );

  return { accessToken, refreshToken };
}

// 활동 인증 관리 API 추가
app.get(
  "/api/admin/activities",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { page = 1, limit = 10, status, category } = req.query;
      const skip = (page - 1) * limit;

      let query = {};
      if (status) query.status = status;
      if (category) query.category = category;

      const activities = await Activity.find(query)
        .populate("userId", "studentId name")
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(parseInt(limit));

      const total = await Activity.countDocuments(query);

      res.json({
        activities,
        currentPage: parseInt(page),
        totalPages: Math.ceil(total / limit),
        totalActivities: total,
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "활동 목록 조회 실패", error: err.message });
    }
  }
);

// 모든 카테고리 조회 (관리자용)
app.get("/api/categories/all", authenticateToken, isAdmin, async (req, res) => {
  try {
    const categories = await Category.find().sort({ order: 1, createdAt: -1 });
    res.json(categories);
  } catch (err) {
    res
      .status(500)
      .json({ message: "카테고리 목록 조회 실패", error: err.message });
  }
});

// 카테고리 수정
app.put(
  "/api/categories/:code",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { code } = req.params;
      const { name, description, points, order, isActive } = req.body;

      const category = await Category.findOneAndUpdate(
        { code },
        {
          name,
          description,
          points,
          order,
          isActive,
          updatedAt: new Date(),
        },
        { new: true }
      );

      if (!category) {
        return res
          .status(404)
          .json({ message: "카테고리를 찾을 수 없습니다." });
      }

      res.json(category);
    } catch (err) {
      res
        .status(400)
        .json({ message: "카테고리 수정 실패", error: err.message });
    }
  }
);

// 비밀번호 초기화 API
app.post(
  "/api/users/:id/reset-password",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const user = await User.findById(id);

      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }

      // 임시 비밀번호 생성 (8자리)
      const temporaryPassword = Math.random().toString(36).slice(-8);

      // 비밀번호 해시화 및 저장
      user.password = temporaryPassword;
      await user.save();

      // 관리자 활동 로깅
      await logAdminAction(req.user.id, "reset_password", {
        targetUserId: id,
        studentId: user.studentId,
      });

      res.json({
        message: "비밀번호가 초기화되었습니다.",
        temporaryPassword,
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "비밀번호 초기화 실패", error: err.message });
    }
  }
);

// 사용자 삭제 API
app.delete("/api/users/:id", authenticateToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // 관리자는 삭제할 수 없음
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    if (user.role === "admin") {
      return res.status(403).json({ message: "관리자는 삭제할 수 없습니다." });
    }

    // 사용자 관련 데이터 삭제
    await Promise.all([
      // 사용자 삭제
      User.findByIdAndDelete(id),
      // 사용자의 활동 내역 삭제
      Activity.deleteMany({ userId: id }),
      // 사용자의 통계 삭제
      UserStats.deleteMany({ userId: id }),
      // 사용자의 알림 삭제
      Notification.deleteMany({ userId: id }),
      // 사용자의 리프레시 토큰 삭제
      RefreshToken.deleteMany({ userId: id }),
    ]);

    // 관리자 활동 로깅
    await logAdminAction(req.user.id, "delete_user", {
      deletedUserId: id,
      studentId: user.studentId,
    });

    res.json({ message: "사용자가 삭제되었습니다." });
  } catch (err) {
    res.status(500).json({ message: "사용자 삭제 실패", error: err.message });
  }
});

// 카테고리 삭제 API 추가
app.delete(
  "/api/categories/:code",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { code } = req.params;

      // 해당 카테고리와 연관된 활동이 있는지 확인
      const hasActivities = await Activity.exists({ category: code });

      if (hasActivities) {
        return res.status(400).json({
          message:
            "이 카테고리와 연관된 활동이 있어 삭제할 수 없습니다. 대신 비활성화를 사용해주세요.",
        });
      }

      const category = await Category.findOneAndDelete({ code });

      if (!category) {
        return res
          .status(404)
          .json({ message: "카테고리를 찾을 수 없습니다." });
      }

      // 관리자 활동 로깅
      await logAdminAction(req.user.id, "delete_category", {
        categoryCode: code,
        categoryName: category.name,
      });

      res.json({
        message: "카테고리가 삭제되었습니다.",
        deletedCategory: category,
      });
    } catch (err) {
      res
        .status(500)
        .json({ message: "카테고리 삭제 실패", error: err.message });
    }
  }
);

// 404 처리는 모든 라우트 정의 후에 마지막으로 배치
app.use((req, res) => {
  res.status(404).json({ message: "요청하신 페이지를 찾을 수 없습니다." });
});

// 단일 카테고리 조회 API 추가
app.get(
  "/api/categories/:code",
  authenticateToken,
  isAdmin,
  async (req, res) => {
    try {
      const { code } = req.params;
      const category = await Category.findOne({ code });

      if (!category) {
        return res
          .status(404)
          .json({ message: "카테고리를 찾을 수 없습니다." });
      }

      res.json(category);
    } catch (err) {
      res
        .status(500)
        .json({ message: "카테고리 조회 실패", error: err.message });
    }
  }
);
