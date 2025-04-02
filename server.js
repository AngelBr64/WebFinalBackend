require('dotenv').config();
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const mime = require('mime-types');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const app = express();
const port = process.env.PORT || 5000;

// Initialize Firebase (versión segura)
if (!process.env.FIREBASE_PRIVATE_KEY) {
  console.error('Error: FIREBASE_PRIVATE_KEY no está definido en las variables de entorno');
  process.exit(1);
}

// Inicialización segura de Firebase usando variables de entorno
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL
});

const db = admin.firestore();

// Middleware Configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// File Upload Configuration
const uploadDir = path.join(__dirname, 'uploads', 'audios');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, `${Date.now()}${ext}`);
    }
  }),
  limits: {
    fileSize: 10 * 1024 * 1024 // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('audio/')) {
      cb(null, true);
    } else {
      cb(new Error('Only audio files are allowed'), false);
    }
  }
});

// Static Files Serving with Proper MIME types
app.use('/uploads/audios', express.static(uploadDir, {
  setHeaders: (res, filePath) => {
    const mimeType = mime.lookup(filePath);
    if (mimeType) {
      res.set('Content-Type', mimeType);
    }
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=31536000');
  }
}));

// API Endpoints
app.post('/create-post', upload.single('audio'), async (req, res) => {
  try {
    const { email, title, description } = req.body;
    const audioFile = req.file;

    if (!email || !title || !description || !audioFile) {
      if (audioFile) fs.unlinkSync(path.join(uploadDir, audioFile.filename));
      return res.status(400).json({ error: 'All fields are required' });
    }

    // Construct full URL
    const audioUrl = `/uploads/audios/${audioFile.filename}`;

    const newPost = {
      email,
      title,
      description,
      audioUrl,
      likes: 0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const docRef = await db.collection('posts').add(newPost);
    
    res.status(201).json({
      success: true,
      post: {
        id: docRef.id,
        ...newPost,
        // Include full URL in response
        audioUrl: `${req.protocol}://${req.get('host')}${audioUrl}`
      }
    });

  } catch (error) {
    console.error('Error creating post:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/posts', async (req, res) => {
  try {
    const snapshot = await db.collection('posts').orderBy('createdAt', 'desc').get();
    const posts = await Promise.all(snapshot.docs.map(async (doc) => {
      const data = doc.data();
      
      // Obtener información del usuario
      const userSnapshot = await db.collection('USERS').where('email', '==', data.email).get();
      let userData = {};
      if (!userSnapshot.empty) {
        const userDoc = userSnapshot.docs[0];
        userData = {
          username: userDoc.data().username,
          avatarUrl: userDoc.data().avatarUrl || null
        };
      }

      return {
        id: doc.id,
        ...data,
        ...userData,
        createdAt: data.createdAt?.toDate()?.toISOString(),
        audioUrl: data.audioUrl.includes('http') ? data.audioUrl 
               : `${req.protocol}://${req.get('host')}${data.audioUrl}`
      };
    }));
    res.json({ posts });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint para actualizar posts
app.put('/update-post/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, description } = req.body;

    if (!title || !description) {
      return res.status(400).json({ error: 'Title and description are required' });
    }

    await db.collection('posts').doc(id).update({
      title,
      description,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true, message: 'Post updated successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint para eliminar posts
app.delete('/delete-post/:id', async (req, res) => {
  try {
    const { id } = req.params;
    
    // Opcional: Eliminar el archivo de audio asociado
    const post = await db.collection('posts').doc(id).get();
    if (post.exists) {
      const audioPath = path.join(uploadDir, post.data().audioUrl.split('/').pop());
      if (fs.existsSync(audioPath)) {
        fs.unlinkSync(audioPath);
      }
    }

    await db.collection('posts').doc(id).delete();
    
    res.json({ success: true, message: 'Post deleted successfully' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/user_posts', async (req, res) => {
  try {
    // Obtener el email del query parameter
    const userEmail = req.query.email;
    
    if (!userEmail) {
      return res.status(400).json({ error: 'Email parameter is required' });
    }

    // Obtener las publicaciones del usuario específico
    const snapshot = await db.collection('posts')
      .where('email', '==', userEmail)
      .orderBy('createdAt', 'desc')
      .get();

    // Procesar las publicaciones igual que en /posts
    const posts = await Promise.all(snapshot.docs.map(async (doc) => {
      const data = doc.data();
      
      // Obtener información del usuario (aunque en este caso es el mismo)
      const userSnapshot = await db.collection('USERS').where('email', '==', data.email).get();
      let userData = {};
      if (!userSnapshot.empty) {
        const userDoc = userSnapshot.docs[0];
        userData = {
          username: userDoc.data().username,
          avatarUrl: userDoc.data().avatarUrl || null
        };
      }

      return {
        id: doc.id,
        ...data,
        ...userData,
        createdAt: data.createdAt?.toDate()?.toISOString(),
        audioUrl: data.audioUrl.includes('http') ? data.audioUrl 
               : `${req.protocol}://${req.get('host')}${data.audioUrl}`
      };
    }));

    res.json({ posts });
  } catch (error) {
    console.error('Error in /user_posts:', error);
    res.status(500).json({ 
      error: 'Error fetching user posts',
      details: error.message 
    });
  }
});

const jwt = require('jsonwebtoken');

// Define la función para generar el token JWT
function generateJWT(userId) {
  const payload = {
    userId: userId,
  };

  // Firma el token con una clave secreta y lo configura para que expire en 1 hora (puedes ajustar esto)
  const token = jwt.sign(payload, 'your-secret-key', { expiresIn: '1h' });

  return token;
}


app.post('/register', async (req, res) => {
  try {
    const { email, password, username } = req.body;
    
    // Validaciones básicas
    if (!email || !password || !username) {
      return res.status(400).json({
        success: false,
        message: 'Todos los campos son requeridos'
      });
    }

    // Verificar si el usuario ya existe
    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (!snapshot.empty) {
      return res.status(400).json({
        success: false,
        message: 'El usuario ya existe'
      });
    }

    // Generar secreto MFA (sin guardar aún en la base de datos)
    const secret = speakeasy.generateSecret({
      name: `Aether:${email}`,
      issuer: 'Aether App'
    });

    // Crear documento temporal en una colección aparte
    const tempUserRef = db.collection('TEMP_USERS').doc();
    await tempUserRef.set({
      email,
      password,
      username,
      mfaSecret: secret.base32,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      expiresAt: new Date(Date.now() + 15 * 60 * 1000) // Expira en 15 minutos
    });

    // Generar QR Code
    QRCode.toDataURL(secret.otpauth_url, (err, imageUrl) => {
      if (err) {
        console.error('Error generando QR:', err);
        return res.status(500).json({
          success: false,
          message: 'Error generando código QR'
        });
      }

      res.status(200).json({
        success: true,
        message: 'Complete el registro con MFA',
        tempUserId: tempUserRef.id,
        mfa: {
          qrCode: imageUrl,
          manualEntryCode: secret.base32
        }
      });
    });

  } catch (error) {
    console.error('Error en registro:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor'
    });
  }
});

app.post('/complete-registration', async (req, res) => {
  try {
    const { tempUserId, token } = req.body;
    
    if (!tempUserId || !token) {
      return res.status(400).json({
        success: false,
        message: 'Datos incompletos'
      });
    }

    // Obtener registro temporal
    const tempUserRef = db.collection('TEMP_USERS').doc(tempUserId);
    const tempUserDoc = await tempUserRef.get();
    
    if (!tempUserDoc.exists) {
      return res.status(404).json({
        success: false,
        message: 'Registro temporal no encontrado o ya expirado'
      });
    }

    const tempUser = tempUserDoc.data();

    // Verificar expiración
    if (new Date(tempUser.expiresAt) < new Date()) {
      await tempUserRef.delete();
      return res.status(401).json({
        success: false,
        message: 'El registro temporal ha expirado. Por favor comienza el proceso nuevamente.'
      });
    }

    // Verificación MFA más robusta
    const verified = speakeasy.totp.verify({
      secret: tempUser.mfaSecret,
      encoding: 'base32',
      token: token,
      window: 2, 
      step: 30 
    });

    if (!verified) {
      return res.status(401).json({
        success: false,
        message: 'Código MFA inválido o expirado. Genera uno nuevo en tu app autenticadora.'
      });
    }

    // Omitir hash de la contraseña
    const password = tempUser.password; 

    // Crear usuario definitivo
    const userRef = await db.collection('USERS').add({
      email: tempUser.email,
      password: password, 
      username: tempUser.username,
      mfaSecret: tempUser.mfaSecret,
      mfaEnabled: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Eliminar temporal
    await tempUserRef.delete();

    const jwtToken = generateJWT(userRef.id); 

    res.json({
      success: true,
      message: 'Registro completado exitosamente',
      userId: userRef.id,
      token: jwtToken
    });

  } catch (error) {
    console.error('Error completando registro:', error);
    res.status(500).json({
      success: false,
      message: 'Error interno del servidor',
      error: error.message
    });
  }
});

app.post('/verify-mfa', async (req, res) => {
  try {
    const { userId, token } = req.body;
    
    // Validación más estricta
    if (!userId || !token || token.length !== 6) {
      return res.status(400).json({
        success: false,
        message: 'Se requieren ID de usuario y token de 6 dígitos'
      });
    }

    const userRef = db.collection('USERS').doc(userId);
    const userDoc = await userRef.get();
    
    if (!userDoc.exists) {
      return res.status(404).json({
        success: false,
        message: 'Usuario no encontrado'
      });
    }

    const userData = userDoc.data();
    const secret = userData.mfaTempSecret;

    if (!secret) {
      return res.status(400).json({
        success: false,
        message: 'Configuración MFA no encontrada para este usuario'
      });
    }

    const verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: token,
      window: 2 
    });

    if (verified) {
      // Actualizar estado MFA
      await userRef.update({
        mfaSecret: secret,
        mfaTempSecret: null,
        mfaEnabled: true
      });

      return res.json({
        success: true,
        message: 'MFA verificado exitosamente'
      });
    } else {
      return res.status(401).json({
        success: false,
        message: 'Código MFA inválido'
      });
    }
  } catch (error) {
    console.error('Error en verificación MFA:', error);
    return res.status(500).json({
      success: false,
      message: 'Error interno al verificar MFA',
      error: error.message
    });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    if (userData.password !== password) {
      return res.status(401).json({
        success: false,
        message: 'Incorrect password'
      });
    }

    res.status(200).json({
      success: true,
      message: 'Login successful',
      user: {
        email: userData.email,
        username: userData.username
      },
      token: 'authentication-token'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: error.message
    });
  }
});

// Obtener perfil de usuario
app.get('/user-profile', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    
    res.json({
      ...userData,
      id: userDoc.id
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Actualizar perfil de usuario
app.put('/update-profile', async (req, res) => {
  try {
    const { email, username, bio } = req.body;
    
    if (!email || !username) {
      return res.status(400).json({ error: 'Email and username are required' });
    }

    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = snapshot.docs[0];
    
    await db.collection('USERS').doc(userDoc.id).update({
      username,
      bio: bio || '',
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    const updatedUser = (await db.collection('USERS').doc(userDoc.id).get()).data();
    
    res.json({
      ...updatedUser,
      id: userDoc.id
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Configuración de Multer para avatares
const avatarUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(__dirname, 'uploads', 'avatars');
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname) || '.jpg';
      cb(null, `${Date.now()}${ext}`);
    }
  }),
  limits: {
    fileSize: 2 * 1024 * 1024
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'), false);
    }
  }
});

// Endpoint para subir avatar
app.post('/upload-avatar', avatarUpload.single('avatar'), async (req, res) => {
  try {
    const { email } = req.body;
    const avatarFile = req.file;

    if (!email || !avatarFile) {
      if (avatarFile) {
        fs.unlinkSync(path.join(__dirname, 'uploads', 'avatars', avatarFile.filename));
      }
      return res.status(400).json({ 
        success: false,
        error: 'Email and avatar file are required' 
      });
    }

    // Verificar que el usuario existe
    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      fs.unlinkSync(path.join(__dirname, 'uploads', 'avatars', avatarFile.filename));
      return res.status(404).json({ 
        success: false,
        error: 'User not found' 
      });
    }

    const userDoc = snapshot.docs[0];
    const currentUser = userDoc.data();
    
    // Eliminar avatar anterior si existe
    if (currentUser.avatarUrl) {
      const oldAvatarPath = path.join(
        __dirname, 
        'uploads', 
        'avatars', 
        currentUser.avatarUrl.split('/').pop()
      );
      if (fs.existsSync(oldAvatarPath)) {
        fs.unlinkSync(oldAvatarPath);
      }
    }

    // Construir la URL del nuevo avatar
    const avatarUrl = `/uploads/avatars/${avatarFile.filename}`;
    const fullAvatarUrl = `${req.protocol}://${req.get('host')}${avatarUrl}`;

    // Actualizar el usuario en Firestore
    await db.collection('USERS').doc(userDoc.id).update({
      avatarUrl: fullAvatarUrl,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({
      success: true,
      avatarUrl: fullAvatarUrl
    });
  } catch (error) {
    console.error('Error uploading avatar:', error);
    if (req.file) {
      fs.unlinkSync(path.join(__dirname, 'uploads', 'avatars', req.file.filename));
    }
    res.status(500).json({ 
      success: false,
      error: error.message 
    });
  }
});

// Servir avatares estáticos
app.use('/uploads/avatars', express.static(path.join(__dirname, 'uploads', 'avatars'), {
  setHeaders: (res, filePath) => {
    const mimeType = mime.lookup(filePath);
    if (mimeType) {
      res.set('Content-Type', mimeType);
    }
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Cache-Control', 'public, max-age=31536000');
  }
}));

// Get comments for a post
app.get('/get-comments', async (req, res) => {
  try {
    const { postId } = req.query;
    
    if (!postId) {
      return res.status(400).json({ error: 'postId is required' });
    }

    const postRef = db.collection('posts').doc(postId);
    const postDoc = await postRef.get();
    
    if (!postDoc.exists) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const commentsSnapshot = await postRef.collection('comments')
      .orderBy('createdAt', 'desc')
      .get();

    const comments = commentsSnapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate()?.toISOString()
    }));

    res.json({ comments });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Agregar al inicio del archivo
const clients = new Map();

app.get('/notifications', (req, res) => {
  const email = req.query.email;
  
  if (!email) {
    return res.status(400).send('Email is required');
  }

  // Configura headers SSE
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive'
  });

  // Guarda la conexión
  const clientId = Date.now();
  clients.set(clientId, { res, email });

  // Envía un mensaje de conexión inicial
  res.write('event: connection\ndata: Connected\n\n');

  // Maneja la desconexión
  req.on('close', () => {
    clients.delete(clientId);
    res.end();
  });
});

// Función para enviar notificaciones
function sendNotificationToUser(email, notification) {
  clients.forEach((client, clientId) => {
    if (client.email === email) {
      try {
        client.res.write(`event: notification\n`);
        client.res.write(`data: ${JSON.stringify(notification)}\n\n`);
      } catch (error) {
        console.error('Error sending SSE:', error);
        clients.delete(clientId);
      }
    }
  });
}

app.get('/get-notifications', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const notificationsRef = db.collection('notifications');
    const query = db.collection('notifications')
    .where('recipient', '==', email)
    .orderBy('createdAt', 'desc');

    // Forzar a no usar caché para desarrollo
    const snapshot = await query.get({ source: 'server' });

    const notifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      // Convertir Timestamp a Date
      createdAt: doc.data().createdAt.toDate().toISOString(),
      readAt: doc.data().readAt?.toDate()?.toISOString()
    }));

    res.json({ success: true, notifications });
  } catch (error) {
    console.error('Error getting notifications:', error);
    res.status(500).json({ 
      success: false,
      error: error.message,
      details: error.details
    });
  }
});

// Función para enviar notificaciones a un usuario
function sendNotificationToUser(email, notification) {
  clients.forEach((client, clientId) => {
    if (client.email === email) {
      try {
        client.res.write(`data: ${JSON.stringify(notification)}\n\n`);
      } catch (error) {
        console.error('Error sending SSE to client:', clientId, error);
        clients.delete(clientId);
      }
    }
  });
}

// Modificar el endpoint de likes para incluir notificaciones personalizadas
app.post('/like-post', async (req, res) => {
  try {
    const { postId, userId } = req.body;
    
    if (!postId || !userId) {
      return res.status(400).json({ error: 'postId and userId are required' });
    }

    const postRef = db.collection('posts').doc(postId);
    const postDoc = await postRef.get();
    
    if (!postDoc.exists) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const postData = postDoc.data();
    
    // Check if user already liked this post
    const likeRef = postRef.collection('likes').doc(userId);
    const likeDoc = await likeRef.get();
    
    if (likeDoc.exists) {
      // Unlike
      await likeRef.delete();
      await postRef.update({
        likes: admin.firestore.FieldValue.increment(-1)
      });
      
      res.json({ success: true, action: 'unliked', likes: (postData.likes || 1) - 1 });
    } else {
      // Like
      await likeRef.set({
        userId,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
      await postRef.update({
        likes: admin.firestore.FieldValue.increment(1)
      });
      
      // Enviar notificación al dueño del post (si no es el mismo usuario)
      if (postData.email !== userId) {
        // Obtener información del usuario que dio like
        const likerUser = await db.collection('USERS').where('email', '==', userId).get();
        let likerUsername = 'Alguien';
        
        if (!likerUser.empty) {
          const likerData = likerUser.docs[0].data();
          likerUsername = likerData.username || likerData.email;
        }
        
        const notification = {
          type: 'like',
          message: `${likerUsername} ha dado like a tu publicación`,
          postId,
          userId,
          username: likerUsername,
          avatarUrl: likerUser.docs[0]?.data()?.avatarUrl || null,
          timestamp: new Date().toISOString(),
          read: false
        };
        
        // Enviar notificación en tiempo real
        sendNotificationToUser(postData.email, notification);
        
        // Guardar notificación en la base de datos
        await db.collection('notifications').add({
          ...notification,
          recipient: postData.email,
          createdAt: admin.firestore.FieldValue.serverTimestamp()
        });
      }
      
      res.json({ success: true, action: 'liked', likes: (postData.likes || 0) + 1 });
    }
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Modificar el endpoint de comentarios para incluir notificaciones personalizadas
app.post('/add-comment', async (req, res) => {
  try {
    const { postId, userId, text, username, avatarUrl } = req.body;
    
    if (!postId || !userId || !text) {
      return res.status(400).json({ error: 'postId, userId and text are required' });
    }

    const postRef = db.collection('posts').doc(postId);
    const postDoc = await postRef.get();
    
    if (!postDoc.exists) {
      return res.status(404).json({ error: 'Post not found' });
    }

    const postData = postDoc.data();
    const commentRef = postRef.collection('comments').doc();
    await commentRef.set({
      userId,
      username: username || 'Anónimo',
      avatarUrl: avatarUrl || null,
      text,
      createdAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Increment comment count
    await postRef.update({
      commentCount: admin.firestore.FieldValue.increment(1)
    });

    // Enviar notificación al dueño del post (si no es el mismo usuario)
    if (postData.email !== userId) {
      const commenterName = username || 'Alguien';
      const notification = {
        type: 'comment',
        message: `${commenterName} ha comentado tu publicación`,
        postId,
        userId,
        username: commenterName,
        avatarUrl: avatarUrl || null,
        commentText: text,
        timestamp: new Date().toISOString(),
        read: false
      };
      
      // Enviar notificación en tiempo real
      sendNotificationToUser(postData.email, notification);
      
      // Guardar notificación en la base de datos
      await db.collection('notifications').add({
        ...notification,
        recipient: postData.email,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      });
    }

    res.json({
      success: true,
      comment: {
        id: commentRef.id,
        userId,
        username: username || 'Anónimo',
        avatarUrl: avatarUrl || null,
        text,
        createdAt: new Date().toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Endpoint para obtener notificaciones históricas
app.get('/get-notifications', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ 
        success: false,
        error: 'Se requiere el email' 
      });
    }

    // Verificar que la colección 'notifications' exista
    const notificationsRef = db.collection('notifications');
    const snapshot = await notificationsRef
      .where('recipient', '==', email)
      .orderBy('createdAt', 'desc')
      .limit(20)
      .get();

    if (snapshot.empty) {
      return res.json({ 
        success: true,
        notifications: [] 
      });
    }

    const notifications = snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: doc.data().createdAt?.toDate()?.toISOString(),
      readAt: doc.data().readAt?.toDate()?.toISOString()
    }));

    res.json({ 
      success: true,
      notifications 
    });
  } catch (error) {
    console.error('Error al obtener notificaciones:', error);
    res.status(500).json({ 
      success: false,
      error: 'Error interno al cargar notificaciones',
      details: error.message 
    });
  }
});

// Endpoint para marcar notificaciones como leídas
app.put('/mark-notification-read', async (req, res) => {
  try {
    const { notificationId } = req.body;
    
    if (!notificationId) {
      return res.status(400).json({ error: 'notificationId is required' });
    }

    await db.collection('notifications').doc(notificationId).update({
      read: true,
      readAt: admin.firestore.FieldValue.serverTimestamp()
    });

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/mark-all-notifications-read', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Obtener todas las notificaciones no leídas
    const snapshot = await db.collection('notifications')
      .where('recipient', '==', email)
      .where('read', '==', false)
      .get();

    // Actualizar todas en un batch
    const batch = db.batch();
    snapshot.docs.forEach(doc => {
      const ref = db.collection('notifications').doc(doc.id);
      batch.update(ref, {
        read: true,
        readAt: admin.firestore.FieldValue.serverTimestamp()
      });
    });

    await batch.commit();
    res.json({ success: true, markedCount: snapshot.size });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// Check if user liked a post
app.get('/check-like', async (req, res) => {
  try {
    const { postId, userId } = req.query;
    
    if (!postId || !userId) {
      return res.status(400).json({ error: 'postId and userId are required' });
    }

    const likeRef = db.collection('posts').doc(postId).collection('likes').doc(userId);
    const likeDoc = await likeRef.get();
    
    res.json({ liked: likeDoc.exists });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Password Recovery Endpoints
const nodemailer = require('nodemailer');
const crypto = require('crypto');

// Configure email transporter
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASSWORD
  }
});

// Generate reset token
function generateToken() {
  return crypto.randomBytes(20).toString('hex');
}

// Request password reset
app.post('/request-password-reset', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Check if user exists
    const userRef = db.collection('USERS').where('email', '==', email);
    const snapshot = await userRef.get();
    
    if (snapshot.empty) {
      // For security, don't reveal if email exists or not
      return res.json({ 
        success: true,
        message: 'If this email exists, a reset link has been sent'
      });
    }

    const userDoc = snapshot.docs[0];
    const user = userDoc.data();

    // Generate token and expiration (1 hour from now)
    const token = generateToken();
    const expires = Date.now() + 3600000; // 1 hour

    // Store token in database
    await db.collection('passwordResets').doc(userDoc.id).set({
      email,
      token,
      expires: new Date(expires),
      used: false
    });

    // Send email with reset link
    const resetUrl = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;
    
    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Recuperación de contraseña - Aether',
      html: `
        <h2>Recuperación de contraseña</h2>
        <p>Hemos recibido una solicitud para restablecer la contraseña de tu cuenta.</p>
        <p>Haz clic en el siguiente enlace para continuar:</p>
        <a href="${resetUrl}">${resetUrl}</a>
        <p>Si no solicitaste este cambio, puedes ignorar este mensaje.</p>
        <p>El enlace expirará en 1 hora.</p>
      `
    };

    await transporter.sendMail(mailOptions);

    res.json({ 
      success: true,
      message: 'If this email exists, a reset link has been sent'
    });

  } catch (error) {
    console.error('Error in password reset request:', error);
    res.status(500).json({ 
      error: 'Error processing password reset',
      details: error.message 
    });
  }
});

// Reset password
app.post('/reset-password', async (req, res) => {
  try {
    const { token, email, newPassword } = req.body;
    
    if (!token || !email || !newPassword) {
      return res.status(400).json({ error: 'Token, email and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Find user
    const userRef = db.collection('USERS').where('email', '==', email);
    const userSnapshot = await userRef.get();
    
    if (userSnapshot.empty) {
      return res.status(404).json({ error: 'User not found' });
    }

    const userDoc = userSnapshot.docs[0];

    // Check if valid reset token exists
    const resetRef = db.collection('passwordResets').doc(userDoc.id);
    const resetDoc = await resetRef.get();
    
    if (!resetDoc.exists) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const resetData = resetDoc.data();

    if (resetData.used || resetData.token !== token || resetData.expires.toDate() < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    // Update password
    await db.collection('USERS').doc(userDoc.id).update({
      password: newPassword,
      updatedAt: admin.firestore.FieldValue.serverTimestamp()
    });

    // Mark token as used
    await resetRef.update({ used: true });

    res.json({ 
      success: true,
      message: 'Password updated successfully'
    });

  } catch (error) {
    console.error('Error resetting password:', error);
    res.status(500).json({ 
      error: 'Error resetting password',
      details: error.message 
    });
  }
});

// Obtener información de un usuario específico
app.get('/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Buscar por ID primero
    let userDoc = await db.collection('USERS').doc(userId).get();
    
    // Si no se encuentra por ID, buscar por email
    if (!userDoc.exists) {
      const userSnapshot = await db.collection('USERS').where('email', '==', userId).get();
      if (!userSnapshot.empty) {
        userDoc = userSnapshot.docs[0];
      } else {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
    }

    const userData = userDoc.data();
    
    // Obtener estadísticas adicionales
    const postsSnapshot = await db.collection('posts')
      .where('userId', '==', userDoc.id)
      .get();
    
    const followersSnapshot = await db.collection('followers')
      .where('followingId', '==', userDoc.id)
      .get();
      
    const followingSnapshot = await db.collection('followers')
      .where('followerId', '==', userDoc.id)
      .get();

    res.json({ 
      success: true,
      user: {
        id: userDoc.id,
        ...userData,
        postsCount: postsSnapshot.size,
        followersCount: followersSnapshot.size,
        followingCount: followingSnapshot.size,
        // Convertir Firestore Timestamp a string ISO
        createdAt: userData.createdAt?.toDate()?.toISOString(),
        updatedAt: userData.updatedAt?.toDate()?.toISOString()
      }
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Error al obtener información del usuario',
      details: error.message 
    });
  }
});

// Obtener publicaciones de un usuario específico
app.get('/user-posts/:userId', async (req, res) => {
  try {
    const { userId } = req.params;
    
    // Buscar usuario primero para verificar que existe
    let userDoc = await db.collection('USERS').doc(userId).get();
    
    if (!userDoc.exists) {
      const userSnapshot = await db.collection('USERS').where('email', '==', userId).get();
      if (userSnapshot.empty) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }
      userDoc = userSnapshot.docs[0];
    }

    const snapshot = await db.collection('posts')
      .where('userId', '==', userDoc.id)
      .orderBy('createdAt', 'desc')
      .get();

    const posts = await Promise.all(snapshot.docs.map(async doc => {
      const data = doc.data();
      
      // Obtener información de likes y comentarios
      const likesSnapshot = await doc.ref.collection('likes').get();
      const commentsSnapshot = await doc.ref.collection('comments').get();
      
      return {
        id: doc.id,
        ...data,
        likes: likesSnapshot.size,
        commentCount: commentsSnapshot.size,
        createdAt: data.createdAt?.toDate()?.toISOString(),
        // Asegurar que la URL del audio sea completa
        audioUrl: data.audioUrl.includes('http') ? data.audioUrl 
               : `${req.protocol}://${req.get('host')}${data.audioUrl}`
      };
    }));

    res.json({ 
      success: true,
      posts 
    });
  } catch (error) {
    res.status(500).json({ 
      error: 'Error al obtener publicaciones del usuario',
      details: error.message 
    });
  }
});




// Verifica la conexión al iniciar el servidor
transporter.verify(function(error, success) {
  if (error) {
    console.log('Error al verificar el transporter:', error);
  } else {
    console.log('Server is ready to take our messages');
  }
});

app.post('/api/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;

  if (!name || !email || !subject || !message) {
    return res.status(400).json({ 
      success: false,
      message: 'Todos los campos son requeridos' 
    });
  }

  try {
    const mailOptions = {
      from: `"Aether Contacto" <${process.env.EMAIL_USER}>`,
      to: 'paquitojaimealburquerque@gmail.com',
      subject: `Contacto Aether: ${subject}`,
      html: `
        <h3>Nuevo mensaje de contacto</h3>
        <p><strong>Nombre:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Asunto:</strong> ${subject}</p>
        <p><strong>Mensaje:</strong></p>
        <p>${message}</p>
      `
    };

    await transporter.sendMail(mailOptions);
    
    res.status(200).json({ 
      success: true,
      message: 'Mensaje enviado con éxito' 
    });
    
  } catch (error) {
    console.error('Error detallado:', {
      message: error.message,
      stack: error.stack,
      code: error.code
    });
    
    res.status(500).json({ 
      success: false,
      message: 'Error al enviar el correo',
      errorDetails: error.message
    });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
  console.log(`Audio files served from: ${uploadDir}`);
});