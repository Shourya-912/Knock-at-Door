# 🚪 Knock at Door - Local Vendor Marketplace

A modern web application that connects **vendors** (street vendors, small business owners, sellers) with **customers** (buyers) in their locality. Vendors can manage their products with photos and prices, and customers can browse available items in real-time with instant notifications.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Installation & Setup](#installation--setup)
- [Database Schema](#database-schema)
- [API Endpoints](#api-endpoints)
- [User Workflows](#user-workflows)
- [Key Features Details](#key-features-details)
- [File Uploads](#file-uploads)
- [Real-time Features](#real-time-features)
- [Contributing](#contributing)
- [License](#license)

---

## 🎯 Overview

**Knock at Door** is a locality-based marketplace that enables:

- **Vendors**: Register, manage products (with photos and prices), manage their profile, and send alerts to customers in different locations
- **Customers**: Browse vendors in their area, view vendor products with photos and prices, receive real-time notifications, and respond to vendor alerts

This application bridges the gap between local vendors and customers by providing a digital platform for product discovery and communication.

---

## ✨ Features

### 🏪 Vendor Features
- **Registration & Authentication**: Secure registration with phone, Aadhar, address, and password
- **Item Management**:
  - ✅ Add items with **photo**, **name**, and **price** (supports units like "250/kg")
  - ✅ Edit item details and photos
  - ✅ Delete unwanted items
  - ✅ View all items in a grid layout with photos
- **Location Management**: Add multiple service localities
- **Alert System**: Send alerts to customers in specific localities with selected items
- **Real-time Notifications**: Receive notifications when customers respond to alerts
- **Profile Management**: View and manage vendor details and address

### 👥 Customer Features
- **Registration & Authentication**: Secure registration with address and Aadhar
- **Vendor Discovery**: Browse all available vendors in locality
- **Item Browsing**: 
  - ✅ View vendor items with **photos** and **prices**
  - ✅ Interactive modal to explore vendor inventory
  - ✅ Uniform image sizing for consistent UI
- **Real-time Alerts**: Receive instant notifications when vendors have items available
- **Alert Management**: 
  - ✅ Dismiss alerts
  - ✅ Indicate waiting for vendor
- **Responsive Design**: Mobile-friendly interface

### 🔐 Security
- Password hashing with **bcrypt**
- Session-based authentication
- Role-based access control (Vendor/Customer)
- Secure file upload validation

---

## 🛠 Technology Stack

### Backend
- **Framework**: Flask 3.0.0
- **Database**: MongoDB (Atlas)
- **Authentication**: bcrypt, Flask Sessions
- **Real-time**: Socket.IO
- **File Upload**: Werkzeug
- **ORM**: Flask-PyMongo

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Responsive design, gradients, animations
- **JavaScript**: Vanilla JS (no frameworks)
- **Icons**: Font Awesome 6.4.2
- **WebSocket**: Socket.IO client

### Infrastructure
- **Hosting**: Gunicorn (production-ready)
- **Database**: MongoDB Atlas (Cloud)
- **Infrastructure as Code**: Terraform (for AWS/Cloud deployment)

---

## 📁 Project Structure

```
knock-at-Door/
├── frontend-flask/
│   ├── app.py                 # Main Flask application (690 lines)
│   ├── app1.py               # Additional app configuration
│   ├── requirement.txt        # Python dependencies
│   │
│   ├── templates/            # HTML Templates
│   │   ├── home_splash.html  # Landing/splash screen
│   │   ├── register.html     # Role selection (Vendor/Customer)
│   │   ├── cust_reg.html     # Customer registration
│   │   ├── vendor_reg.html   # Vendor registration with items
│   │   ├── Login.html        # Unified login
│   │   ├── customer_home.html # Customer dashboard
│   │   └── vendor_home.html  # Vendor dashboard
│   │
│   ├── static/
│   │   ├── css/
│   │   │   ├── animate.css   # Animations
│   │   │   ├── splash.css    # Landing page styles
│   │   │   ├── login.css     # Login page styles
│   │   │   ├── register.css  # Registration styles
│   │   │   ├── intf_reg.css  # Interface registration styles
│   │   │   ├── customer_home.css
│   │   │   └── vendor_home.css
│   │   ├── images/           # Static images
│   │   └── uploads/          # User-uploaded item photos
│   │
│   └── mongodb/              # MongoDB configuration
│
└── terraform/                # Infrastructure as Code
    ├── main.tf
    ├── outputs.tf
    ├── variable.tf
    └── terraform.tfvars
```

---

## 🚀 Installation & Setup

### Prerequisites
- Python 3.8+
- MongoDB Atlas account (Free tier available)
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/knock-at-Door.git
cd knock-at-Door/frontend-flask
```

### Step 2: Create Virtual Environment
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Mac/Linux
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirement.txt
# Additional required packages:
pip install flask-pymongo bcrypt flask-socketio python-socketio
```

### Step 4: Configure MongoDB
1. Create a MongoDB Atlas account at [mongodb.com](https://www.mongodb.com)
2. Create a cluster and get your connection string
3. Update the connection string in `app.py` line 26:
   ```python
   app.config["MONGO_URI"] = "your_mongodb_connection_string"
   ```

### Step 5: Run Application
```bash
python app.py
```

Application will be available at `http://localhost:5000`

---

## 💾 Database Schema

### Collections

#### 1. **users** (Authentication)
```javascript
{
  _id: ObjectId,
  first_name: String,
  last_name: String,
  phone: String (unique),
  aadhar: String,
  password: String (hashed),
  role: "customer" | "vendor"
}
```

#### 2. **customers**
```javascript
{
  _id: ObjectId,
  user_id: String (ref: users._id),
  first_name: String,
  last_name: String,
  phone: String,
  aadhar: String,
  house_no: String,
  locality: String,
  state: String,
  city: String,
  pincode: String,
  address: String
}
```

#### 3. **vendors**
```javascript
{
  _id: ObjectId,
  user_id: String (ref: users._id),
  first_name: String,
  last_name: String,
  phone: String,
  aadhar: String,
  area: String,
  city: String,
  state: String,
  pincode: String,
  items: [
    {
      _id: ObjectId,
      name: String,
      price: String (supports units: "100", "250/kg"),
      photo: String (file path)
    }
  ],
  localities: [
    {
      _id: ObjectId,
      name: String
    }
  ]
}
```

#### 4. **alerts**
```javascript
{
  _id: ObjectId,
  vendor_id: String,
  vendor_name: String,
  vendor_phone: String,
  customer_id: String,
  customer_name: String,
  customer_phone: String,
  locality: String,
  area: String,
  city: String,
  vendor_items: Array,
  status: "active" | "dismissed" | "waiting",
  timestamp: Date
}
```

---

## 🔌 API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Home/splash page |
| GET/POST | `/register` | Role selection |
| GET/POST | `/cust_reg` | Customer registration |
| GET/POST | `/vendor_reg` | Vendor registration |
| GET/POST | `/login` | Login (both roles) |
| GET | `/logout` | Logout & session clear |

### Customer Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/customer_home` | Customer dashboard with vendor list |
| GET | `/get_alerts` | View all customer alerts |
| POST | `/dismiss_alert` | Dismiss a notification |
| POST | `/customer_wait` | Notify vendor customer is waiting |

### Vendor Routes
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/vendor_home` | Vendor dashboard with items |
| POST | `/add_item` | Add item (registration) |
| POST | `/add_item_loggedin` | Add item (after login) |
| POST | `/edit_item` | Edit item details & photo |
| POST | `/delete_item` | Delete item |
| POST | `/send_alert` | Send alert to customers |

---

## 👥 User Workflows

### 🧑‍🌾 Vendor Workflow

1. **Registration**
   - Enter personal details (name, phone, Aadhar)
   - Add items with photo, name, and price
   - Add service localities
   - Set address and password

2. **Dashboard (Post-Login)**
   - View all listed items with photos
   - Edit item details (photo, name, price)
   - Delete items
   - Add new items via modal
   - Send alerts to customers in specific localities

3. **Notifications**
   - Receive real-time notification when customer responds
   - See customer details (name, phone)

### 👤 Customer Workflow

1. **Registration**
   - Enter personal details (name, phone, Aadhar, address)
   - Set password

2. **Dashboard (Post-Login)**
   - Browse vendors in locality
   - Click vendor name or **"View Items"** button
   - See vendor's items with photos and prices
   - Close modal to go back

3. **Notifications**
   - Receive alert when vendor has items
   - See vendor details and available items
   - Dismiss alert or indicate waiting status

---

## 🎨 Key Features Details

### Item Management System
- **Photos**: Stored in `static/uploads/` with validation
- **Price Format**: Flexible text field supporting "100", "250/kg", "50 per piece"
- **Image Sizing**: Consistent 180px height for vendor items, 180px for customer view
- **Edit Modal**: Complete form to update photo, name, and price
- **Delete Protection**: Confirmation dialog before deletion

### Real-time Notification System
- **WebSocket**: Socket.IO for instant notifications
- **Customer Alerts**: Popup notifications with vendor details
- **Vendor Notifications**: Toast notification when customers respond
- **No Refresh**: Users don't need to refresh to see new alerts

### Responsive Design
- Mobile-first approach
- CSS Grid for item display
- Flexible layouts using flexbox
- Smooth animations and transitions

---

## 📸 File Uploads

### Upload Configuration
- **Folder**: `static/uploads/`
- **Allowed Types**: PNG, JPG, JPEG, GIF
- **Security**: 
  - Filename sanitization with `secure_filename()`
  - Extension validation
  - Size validation (handled by browser)

### Item Photo Handling
```python
if item_photo and allowed_file(item_photo.filename):
    filename = secure_filename(item_photo.filename)
    photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    item_photo.save(photo_path)
    item_to_update["photo"] = photo_path.replace("static/", "")
```

---

## ⚡ Real-time Features

### Socket.IO Implementation

**Server Events**:
- `register_user`: Register customer/vendor to receive updates
- `new_alert`: Send alert to customer
- `customer_wait`: Notify vendor customer is waiting
- `connect`/`disconnect`: Connection lifecycle

**JavaScript Integration**:
```javascript
const socket = io();
socket.on('new_alert', function(data) {
  showNotification(data);
});
```

---

## 🔧 Configuration

### Flask Configuration
```python
app.secret_key = "shourya_secret"  # Change this in production
app.config["MONGO_URI"] = "your_mongodb_uri"
app.config["UPLOAD_FOLDER"] = os.path.join("static", "uploads")
```

### MongoDB Connection
Uses MongoDB Atlas cloud service with:
- Automatic backups
- SSL/TLS encryption
- IP whitelist security

---

## 🌳 Environment Variables

Create a `.env` file (not included in repo):
```
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/dbname
FLASK_ENV=production
SECRET_KEY=your_secret_key
```

---

## 🧪 Testing

### Manual Testing Checklist

**Vendor Flow**:
- [ ] Register as vendor
- [ ] Add items with photo
- [ ] Edit item details
- [ ] Delete item
- [ ] Send alert to locality
- [ ] Receive customer wait notification

**Customer Flow**:
- [ ] Register as customer
- [ ] View vendor list
- [ ] Click vendor to see items
- [ ] Receive vendor alert
- [ ] Dismiss/Wait on alert

---

## 🚀 Deployment

### Using Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Using Terraform (AWS/Cloud)
```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

### Docker (Optional)
```dockerfile
FROM python:3.12
WORKDIR /app
COPY requirement.txt .
RUN pip install -r requirement.txt
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
```

---

## 📊 Statistics

- **Total Routes**: 16
- **Database Collections**: 4
- **HTML Templates**: 7
- **CSS Files**: 6
- **Supported File Types**: 4 (PNG, JPG, JPEG, GIF)
- **Real-time Socket Events**: 4+
- **Lines of Backend Code**: 690+

---

## 🐛 Known Issues & Future Improvements

### Current Limitations
- DNS resolution timeout (MongoDB connection issue in some networks)
- No payment integration
- No chat feature
- Limited to locality-based matching

### Planned Features
- 💳 Payment gateway integration (Razorpay/Stripe)
- 💬 Direct messaging between vendor and customer
- 📍 Google Maps integration for better location
- ⭐ Rating and review system
- 🔍 Advanced search and filtering
- 📱 Mobile app (React Native/Flutter)
- 🌍 Multi-language support

---

## 📝 Requirements

```
Flask==3.0.0
gunicorn==21.2.0
flask-pymongo
bcrypt
flask-socketio
python-socketio
python-engineio
Werkzeug
```

---

## 👨‍💻 Author

**Shourya Chourasiya**
- Email: shourchourasia912@gmail.com
- GitHub: @SHCHOURA

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Email: shourchourasia912@gmail.com

---

## 🎓 Learning Resources

This project demonstrates:
- Flask web framework fundamentals
- MongoDB NoSQL database design
- Real-time communication with WebSockets
- Secure authentication (bcrypt hashing)
- File upload handling and validation
- Responsive web design (CSS Grid, Flexbox)
- Session management
- REST API design patterns
- Frontend form handling with JavaScript

---

## 🙏 Acknowledgments

- Flask documentation and community
- MongoDB documentation
- Font Awesome for icons
- Socket.IO for real-time features

---

**Last Updated**: April 10, 2026

---

## 📈 Project Statistics

- **Total Files**: 15+
- **Total Lines of Code**: 1000+
- **Database Size**: Starting from ~5MB (MongoDB Atlas free tier)
- **Frontend Assets**: 10+ CSS files, 15+ HTML templates
- **Real-time Connections**: WebSocket enabled

---

⭐ If you find this project useful, please consider giving it a star on GitHub!
