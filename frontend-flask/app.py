from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt
from datetime import datetime
from flask import jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
import os
import re


app = Flask(__name__)
app.secret_key = "shourya_secret"
socketio = SocketIO(app, cors_allowed_origins="*")

# Upload folder configuration
UPLOAD_FOLDER = os.path.join("static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def is_valid_phone(phone):
    """
    Validate Indian phone number
    - Exactly 10 digits
    - Starts with 6, 7, 8, or 9
    - No special characters
    """
    if not phone or not isinstance(phone, str):
        return False
    
    phone = phone.strip()
    
    # Check if exactly 10 digits
    if not re.match(r'^\d{10}$', phone):
        return False
    
    # Check if starts with 6, 7, 8, or 9
    if phone[0] not in ['6', '7', '8', '9']:
        return False
    
    return True

def is_valid_aadhar(aadhar):
    """
    Validate Indian Aadhar number
    - Exactly 12 digits
    - No special characters
    """
    if not aadhar or not isinstance(aadhar, str):
        return False
    
    aadhar = aadhar.strip()
    
    # Check if exactly 12 digits and all numeric
    if not re.match(r'^\d{12}$', aadhar):
        return False
    
    return True

# MongoDB Config
app.config["MONGO_URI"] = "mongodb+srv://shourchourasia912:Knock912@cluster0.k07ix.mongodb.net/knockatdoor?retryWrites=true&w=majority"
mongo = PyMongo(app)

users_col = mongo.db.users
vendors_col = mongo.db.vendors
customers_col = mongo.db.customers
alerts_col = mongo.db.alerts
ratings_col = mongo.db.ratings

# HOME SPLASH
@app.route("/")
def home():
    return render_template("home_splash.html")

# REGISTER PAGE (Role Selection)
@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")

# CUSTOMER REGISTRATION
@app.route("/cust_reg", methods=["GET", "POST"])
def cust_reg():
    if request.method == "POST":
        first_name = request.form.get("first_name", "")
        last_name = request.form.get("last_name", "")
        phone = request.form.get("phone", "")
        aadhar = request.form.get("aadhar", "")
        house_no = request.form.get("house_no", "")
        locality = request.form.get("locality", "")
        area = request.form.get("area", "")
        state = request.form.get("state", "")
        city = request.form.get("city", "")
        pincode = request.form.get("pincode", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate required fields
        if not all([first_name, last_name, phone, locality, area, state, password, confirm_password]):
            return "Please fill all required fields"

        # Validate phone number
        if not is_valid_phone(phone):
            return "Invalid phone number. Please enter a valid 10-digit Indian phone number starting with 6, 7, 8, or 9"

        # Validate Aadhar number (if provided)
        if aadhar and not is_valid_aadhar(aadhar):
            return "Invalid Aadhar number. Please enter a valid 12-digit Aadhar number"

        # Validate passwords match
        if password != confirm_password:
            return "Passwords do not match"

        # Check if phone already exists
        if users_col.find_one({"phone": phone}):
            return "Phone number already registered"

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create full address
        address = f"{house_no}, {locality}, {area}, {city}, {state} {pincode}".replace(", , ", ", ")

        try:
            # Save user
            user_id = users_col.insert_one({
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "aadhar": aadhar,
                "password": hashed_password,
                "role": "customer"
            }).inserted_id

            # Save customer info
            customers_col.insert_one({
                "user_id": str(user_id),
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "aadhar": aadhar,
                "house_no": house_no,
                "locality": locality,
                "area": area,
                "state": state,
                "city": city,
                "pincode": pincode,
                "address": address
            })

            print(f"✓ Customer registered: {first_name} {last_name}, Phone: {phone}")
            return redirect(url_for("login"))
        
        except Exception as e:
            print(f"✗ Error: {str(e)}")
            return f"Registration failed: {str(e)}"

    return render_template("cust_reg.html")


# VENDOR REGISTRATION
@app.route("/vendor_reg", methods=["GET", "POST"])
def vendor_reg():
    if request.method == "POST":
        try:
            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            phone = request.form.get("phone", "").strip()
            aadhar = request.form.get("aadhar", "").strip()
            area = request.form.get("area", "").strip()
            state = request.form.get("state", "").strip()
            city = request.form.get("city", "").strip()
            pincode = request.form.get("pincode", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Validate required fields
            if not all([first_name, last_name, phone, aadhar, area, state, city, pincode, password, confirm_password]):
                return "Please fill all required fields"

            # Validate phone number
            if not is_valid_phone(phone):
                return "Invalid phone number. Please enter a valid 10-digit phone number"

            # Validate Aadhar number
            if not is_valid_aadhar(aadhar):
                return "Invalid Aadhar number. Please enter a valid 12-digit Aadhar number"

            # Validate passwords match
            if password != confirm_password:
                return "Passwords do not match"

            # Check if phone already exists
            if users_col.find_one({"phone": phone}):
                return "Phone number already registered"

            # Get items (multiple, now with photo and price)
            items = []
            for i in range(1, 10):
                item_name = request.form.get(f"item{i}_name", "").strip()
                item_price = request.form.get(f"item{i}_price", "").strip()
                item_photo = request.files.get(f"item{i}_photo")
                if item_name and item_price and item_photo and allowed_file(item_photo.filename):
                    filename = secure_filename(item_photo.filename)
                    photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    item_photo.save(photo_path)
                    items.append({
                        "_id": ObjectId(),
                        "photo": photo_path.replace("static/", ""),
                        "price": item_price,
                        "name": item_name
                    })

            # item_extra[] (dynamically added)
            item_extra_names = request.form.getlist("item_extra_name[]")
            item_extra_prices = request.form.getlist("item_extra_price[]")
            item_extra_photos = request.files.getlist("item_extra_photo[]")
            for idx, item_name in enumerate(item_extra_names):
                item_name = item_name.strip()
                item_price = item_extra_prices[idx].strip() if idx < len(item_extra_prices) else ""
                item_photo = item_extra_photos[idx] if idx < len(item_extra_photos) else None
                if item_name and item_price and item_photo and allowed_file(item_photo.filename):
                    filename = secure_filename(item_photo.filename)
                    photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    item_photo.save(photo_path)
                    items.append({
                        "_id": ObjectId(),
                        "photo": photo_path.replace("static/", ""),
                        "price": item_price,
                        "name": item_name
                    })

            if not items:
                return "Please add at least one item (with photo and price)"

            # Get localities (multiple)
            localities = []
            # locality1, locality2 से शुरू
            for i in range(1, 10):
                locality_name = request.form.get(f"locality{i}", "").strip()
                if locality_name:
                    localities.append({"_id": ObjectId(), "name": locality_name})
            
            # locality_extra[] से शुरू (dynamically added)
            locality_extras = request.form.getlist("locality_extra[]")
            for locality_name in locality_extras:
                if locality_name.strip():
                    localities.append({"_id": ObjectId(), "name": locality_name.strip()})

            if not localities:
                return "Please add at least one locality"

            # Hash password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # Save user
            user_id = users_col.insert_one({
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "aadhar": aadhar,
                "password": hashed_password,
                "role": "vendor"
            }).inserted_id

            # Save vendor info
            vendors_col.insert_one({
                "user_id": str(user_id),
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "aadhar": aadhar,
                "items": items,
                "localities": localities,
                "area": area,
                "state": state,
                "city": city,
                "pincode": pincode
            })

            print(f"✓ Vendor registered: {first_name} {last_name}, Phone: {phone}")
            print(f"  Items: {[item['name'] for item in items]}")
            print(f"  Localities: {[loc['name'] for loc in localities]}")
            
            return redirect(url_for("login"))

        except Exception as e:
            print(f"✗ Vendor Registration Error: {str(e)}")
            return f"Registration failed: {str(e)}"

    return render_template("vendor_reg.html")

# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form["phone"]
        password = request.form["password"].encode('utf-8')

        user = users_col.find_one({"phone": phone})
        
        if user:
            print(f"User found: {user['first_name']} {user['last_name']}, Role: {user['role']}")
            
            if bcrypt.checkpw(password, user["password"]):
                session["user_id"] = str(user["_id"])
                session["role"] = user["role"]
                
                print(f"✓ Login successful - User ID: {session['user_id']}, Role: {session['role']}")

                if user["role"] == "customer":
                    return redirect(url_for("customer_home"))
                else:
                    return redirect(url_for("vendor_home"))
            else:
                print(f"✗ Password incorrect for {phone}")
                return "Invalid phone or password"
        else:
            print(f"✗ User not found: {phone}")
            return "Invalid phone or password"

    return render_template("login.html")

# CUSTOMER HOME PAGE
@app.route("/customer_home")
def customer_home():
    if "user_id" not in session or session.get("role") != "customer":
        return redirect(url_for("login"))

    print(f"Session user_id: {session['user_id']}")
    print(f"Session role: {session.get('role')}")

    customer = customers_col.find_one({"user_id": session["user_id"]})
    
    if not customer:
        print(f"✗ Customer not found for user_id: {session['user_id']}")
        return redirect(url_for("login"))

    # Get customer's city and locality
    customer_city = customer.get("city", "")
    customer_locality = customer.get("locality", "")
    
    # Find vendors only from same city and locality
    vendors = list(vendors_col.find({
        "city": {"$regex": customer_city, "$options": "i"},
        "localities": {
            "$elemMatch": {
                "name": {"$regex": customer_locality, "$options": "i"}
            }
        }
    }))

    print(f"✓ Customer Home loaded: {customer['first_name']} {customer['last_name']}")
    print(f"  Locality: {customer_locality}, City: {customer_city}")
    print(f"  Found {len(vendors)} vendors in this locality")

    # Format vendors properly - only basic details
    vendor_list = []
    for v in vendors:
        vendor_items = []
        if "items" in v and isinstance(v["items"], list):
            vendor_items = v["items"]  # Keep full item objects with photo and price
        
        vendor_list.append({
            "id": str(v["_id"]),
            "name": f"{v['first_name']} {v['last_name']}",
            "phone": v["phone"],
            "city": v.get("city", ""),
            "vendor_items": vendor_items  # Full item objects
        })

    return render_template(
        "customer_home.html",
        customer_name=f"{customer['first_name']} {customer['last_name']}",
        customer_phone=customer["phone"],
        customer_address=customer.get("address", ""),
        vendors=vendor_list
    )   


#CUSTOMER GET ALERTS
@app.route("/get_alerts")
def get_alerts():
    if "user_id" not in session or session.get("role") != "customer":
        return redirect(url_for("login"))
    
    customer = customers_col.find_one({"user_id": session["user_id"]})
    alerts = list(alerts_col.find({
        "customer_id": customer["user_id"],
        "status": "active"
    }).sort("timestamp", -1))
    
    return render_template("alerts.html", alerts=alerts)

# VENDOR HOME PAGE
@app.route("/vendor_home")
def vendor_home():
    if "user_id" not in session or session.get("role") != "vendor":
        return redirect(url_for("login"))

    vendor = vendors_col.find_one({"user_id": session["user_id"]})
    
    if not vendor:
        return redirect(url_for("login"))

    # formatting items properly along with price and photo
    items = [{"id": str(i["_id"]), "name": i.get("name", ""), "photo": i.get("photo", ""), "price": i.get("price", "")} for i in vendor.get("items", [])]
    
    # formatting Locations properly
    locations = []
    for loc in vendor.get("localities", []):
        locations.append({
            "id": str(loc["_id"]),
            "locality": loc.get("name", ""),
            "area": vendor.get("area", ""),
            "city": vendor.get("city", "")
        })

    # Create full address
    address = f"{vendor.get('area', '')}, {vendor.get('city', '')}, {vendor.get('state', '')}, {vendor.get('pincode', '')}"

    print(f"✓ Vendor Home loaded: {vendor['first_name']} {vendor['last_name']}")
    print(f"  Items: {[item['name'] for item in items]}")
    print(f"  Localities: {[loc['locality'] for loc in locations]}")

    return render_template(
        "vendor_home.html",
        vendor_name=f"{vendor['first_name']} {vendor['last_name']}",
        vendor_phone=vendor["phone"],
        vendor_address=address,
        vendor_id=str(vendor["_id"]),
        items=items,
        locations=locations
    )

# ADD ITEM (Vendor)
@app.route("/add_item", methods=["POST"])
def add_item():
    if "user_id" not in session:
        return redirect(url_for("login"))

    item_name = request.form["item"]
    vendors_col.update_one(
        {"user_id": session["user_id"]},
        {"$push": {"items": {"_id": ObjectId(), "name": item_name}}}
    )
    return redirect(url_for("vendor_home"))


# ADD ITEM (Vendor - After Login)
@app.route("/add_item_loggedin", methods=["POST"])
def add_item_loggedin():
    if "user_id" not in session or session.get("role") != "vendor":
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    item_name = request.form.get("item_name", "").strip()
    item_price = request.form.get("item_price", "").strip()
    item_photo = request.files.get("item_photo")
    
    if not item_name or not item_price:
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    if not item_photo or not allowed_file(item_photo.filename):
        return jsonify({"success": False, "message": "Invalid photo file"}), 400
    
    try:
        vendor = vendors_col.find_one({"user_id": session["user_id"]})
        if not vendor:
            return jsonify({"success": False, "message": "Vendor not found"}), 404
        
        # Save the photo
        filename = secure_filename(item_photo.filename)
        photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        item_photo.save(photo_path)
        
        # Create new item
        new_item = {
            "_id": ObjectId(),
            "name": item_name,
            "price": item_price,
            "photo": photo_path.replace("static/", "")
        }
        
        # Add item to vendor's items array
        vendors_col.update_one(
            {"user_id": session["user_id"]},
            {"$push": {"items": new_item}}
        )
        
        print(f"✓ Item added: {item_name}, Price: {item_price}")
        return jsonify({"success": True, "message": "Item added successfully"})
    
    except Exception as e:
        print(f"✗ Error adding item: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# EDIT ITEM (Vendor)
@app.route("/edit_item", methods=["POST"])
def edit_item():
    if "user_id" not in session or session.get("role") != "vendor":
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    item_id = request.form.get("item_id")
    item_name = request.form.get("item_name", "").strip()
    item_price = request.form.get("item_price", "").strip()
    item_photo = request.files.get("item_photo")
    
    if not item_id or not item_name or not item_price:
        return jsonify({"success": False, "message": "Missing required fields"}), 400
    
    try:
        vendor = vendors_col.find_one({"user_id": session["user_id"]})
        if not vendor:
            return jsonify({"success": False, "message": "Vendor not found"}), 404
        
        # Find the item to update
        item_to_update = None
        for item in vendor.get("items", []):
            if str(item["_id"]) == item_id:
                item_to_update = item
                break
        
        if not item_to_update:
            return jsonify({"success": False, "message": "Item not found"}), 404
        
        # Update item data
        item_to_update["name"] = item_name
        item_to_update["price"] = item_price
        
        # Handle photo upload if provided
        if item_photo and allowed_file(item_photo.filename):
            filename = secure_filename(item_photo.filename)
            photo_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            item_photo.save(photo_path)
            item_to_update["photo"] = photo_path.replace("static/", "")
        
        # Update vendor with new items array
        vendors_col.update_one(
            {"user_id": session["user_id"]},
            {"$set": {"items": vendor["items"]}}
        )
        
        print(f"✓ Item updated: {item_name}, Price: {item_price}")
        return jsonify({"success": True, "message": "Item updated successfully"})
    
    except Exception as e:
        print(f"✗ Error updating item: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# DELETE ITEM (Vendor)
@app.route("/delete_item", methods=["POST"])
def delete_item():
    if "user_id" not in session or session.get("role") != "vendor":
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    data = request.get_json()
    item_id = data.get("item_id")
    
    if not item_id:
        return jsonify({"success": False, "message": "Missing item_id"}), 400
    
    try:
        vendor = vendors_col.find_one({"user_id": session["user_id"]})
        if not vendor:
            return jsonify({"success": False, "message": "Vendor not found"}), 404
        
        # Find and remove the item
        items = vendor.get("items", [])
        items_after_delete = [item for item in items if str(item["_id"]) != item_id]
        
        if len(items_after_delete) == len(items):
            return jsonify({"success": False, "message": "Item not found"}), 404
        
        # Update vendor with new items array
        vendors_col.update_one(
            {"user_id": session["user_id"]},
            {"$set": {"items": items_after_delete}}
        )
        
        print(f"✓ Item deleted: {item_id}")
        return jsonify({"success": True, "message": "Item deleted successfully"})
    
    except Exception as e:
        print(f"✗ Error deleting item: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# SEND ALERT (Vendor)
@app.route("/send_alert", methods=["POST"])
def send_alert():
    if "user_id" not in session or session.get("role") != "vendor":
        return jsonify({"error": "Unauthorized"}), 401
    
    locality = request.form.get("locality")
    area = request.form.get("area")
    city = request.form.get("city")
    
    vendor = vendors_col.find_one({"user_id": session["user_id"]})
    user = users_col.find_one({"_id": ObjectId(session["user_id"])})
    
    if not vendor or not user:
        return jsonify({"error": "Vendor not found"}), 404
    
    # Find all customers in this locality and city
    customers_in_locality = list(customers_col.find({
        "locality": {"$regex": locality, "$options": "i"},
        "city": {"$regex": city, "$options": "i"}
    }))
    
    if not customers_in_locality:
        return jsonify({"message": "No customers found in this locality"}), 200
    
    # Create alert for each customer in that locality
    alerts_created = 0
    for customer in customers_in_locality:
        alert = {
            "vendor_id": session["user_id"],
            "vendor_name": f"{user['first_name']} {user['last_name']}",
            "vendor_phone": user["phone"],
            "vendor_items": [item["name"] for item in vendor.get("items", [])],
            "customer_id": customer["user_id"],
            "customer_name": f"{customer['first_name']} {customer['last_name']}",
            "locality": locality,
            "area": area,
            "city": city,
            "message": "Vendor is available in your area",
            "timestamp": datetime.utcnow(),
            "status": "active",
            "read": False
        }
        alert_id = alerts_col.insert_one(alert).inserted_id
        alerts_created += 1

        # Send real-time WebSocket notification to customer
        emit_data = {
            "alert_id": str(alert_id),
            "vendor_id": session["user_id"],
            "vendor_name": alert["vendor_name"],
            "vendor_phone": alert["vendor_phone"],
            "vendor_items": alert["vendor_items"],
            "locality": alert["locality"],
            "city": alert["city"],
            "message": alert["message"]
        }
        socketio.emit('new_alert', emit_data, room=customer["user_id"])
        print(f"  → Alert {alert_id} sent to customer {customer['user_id']} ({customer['first_name']} {customer['last_name']})")
    
    print(f"✓ Alert sent to {alerts_created} customers in {locality}, {city}")
    return jsonify({
        "message": f"Alert sent successfully to {alerts_created} customers",
        "customers_notified": alerts_created
    })

# DISMISS ALERT (Customer)
@app.route("/dismiss_alert", methods=["POST"])
def dismiss_alert():
    if "user_id" not in session or session.get("role") != "customer":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    alert_id = data.get("alert_id")
    
    if not alert_id:
        return jsonify({"error": "Alert ID required"}), 400
    
    try:
        result = alerts_col.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": "dismissed"}}
        )
        print(f"✓ Alert {alert_id} dismissed by customer {session['user_id']}")
        return jsonify({"message": "Alert dismissed", "modified_count": result.modified_count})
    except Exception as e:
        print(f"✗ Error dismissing alert: {str(e)}")
        return jsonify({"error": str(e)}), 500


# CUSTOMER WAIT NOTIFICATION (Customer)
@app.route("/customer_wait", methods=["POST"])
def customer_wait():
    print(f"\n--- CUSTOMER WAIT REQUEST ---")
    print(f"Session user_id: {session.get('user_id')}, Role: {session.get('role')}")
    
    if "user_id" not in session or session.get("role") != "customer":
        print(f"✗ Authorization failed - Not logged in or not a customer")
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    alert_id = data.get("alert_id")
    vendor_id = data.get("vendor_id")
    
    print(f"Alert ID: {alert_id}")
    print(f"Vendor ID (user_id): {vendor_id}")
    print(f"Active socket rooms: {list(user_socket_map.keys())}")
    
    if not alert_id or not vendor_id:
        print(f"✗ Missing required fields")
        return jsonify({"error": "Alert ID and Vendor ID required"}), 400
    
    try:
        # Get customer info
        customer = customers_col.find_one({"user_id": session["user_id"]})
        if not customer:
            print(f"✗ Customer not found in database")
            return jsonify({"error": "Customer not found"}), 404
        
        print(f"Customer found: {customer['first_name']} {customer['last_name']}")
        
        # Update alert status to 'waiting'
        result = alerts_col.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": "waiting"}}
        )
        print(f"Alert updated: {result.modified_count} documents modified")
        
        # Send notification to vendor via WebSocket
        emit_data = {
            "customer_name": f"{customer['first_name']} {customer['last_name']}",
            "customer_phone": customer["phone"],
            "message": "Customer is waiting! Please arrive soon.",
            "alert_id": alert_id
        }
        
        print(f"Emitting 'customer_wait' event to room: {vendor_id}")
        socketio.emit('customer_wait', emit_data, room=vendor_id)
        
        if vendor_id in user_socket_map:
            print(f"✓ Vendor {vendor_id} is connected (socket: {user_socket_map[vendor_id]})")
        else:
            print(f"⚠ Vendor {vendor_id} is NOT currently connected (but message queued)")
        
        print(f"✓ Customer {session['user_id']} waiting for vendor {vendor_id}")
        return jsonify({"message": "Vendor notified", "status": "waiting"})
    
    except Exception as e:
        print(f"✗ Error notifying vendor: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


# SUBMIT RATING (Customer rates Vendor)
@app.route("/submit_rating", methods=["POST"])
def submit_rating():
    if "user_id" not in session or session.get("role") != "customer":
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.json
    vendor_id = data.get("vendor_id")
    rating = data.get("rating")  # 1-5 stars
    review = data.get("review", "").strip()
    
    if not vendor_id or not rating:
        return jsonify({"error": "Vendor ID and rating are required"}), 400
    
    try:
        rating = int(rating)
        if rating < 1 or rating > 5:
            return jsonify({"error": "Rating must be between 1 and 5"}), 400
    except ValueError:
        return jsonify({"error": "Invalid rating value"}), 400
    
    try:
        customer = customers_col.find_one({"user_id": session["user_id"]})
        vendor = vendors_col.find_one({"_id": ObjectId(vendor_id)})
        
        if not customer or not vendor:
            return jsonify({"error": "Customer or vendor not found"}), 404
        
        # Check if customer already rated this vendor
        existing_rating = ratings_col.find_one({
            "vendor_id": vendor_id,
            "customer_id": session["user_id"]
        })
        
        if existing_rating:
            # Update existing rating
            ratings_col.update_one(
                {"_id": existing_rating["_id"]},
                {"$set": {
                    "rating": rating,
                    "review": review,
                    "timestamp": datetime.utcnow()
                }}
            )
            print(f"✓ Rating updated by customer {session['user_id']} for vendor {vendor_id}")
        else:
            # Insert new rating
            ratings_col.insert_one({
                "vendor_id": vendor_id,
                "customer_id": session["user_id"],
                "customer_name": f"{customer['first_name']} {customer['last_name']}",
                "customer_phone": customer["phone"],
                "rating": rating,
                "review": review,
                "timestamp": datetime.utcnow()
            })
            print(f"✓ New rating submitted by customer {session['user_id']} for vendor {vendor_id}: {rating} stars")
        
        return jsonify({"message": "Rating submitted successfully", "rating": rating})
    
    except Exception as e:
        print(f"✗ Error submitting rating: {str(e)}")
        return jsonify({"error": str(e)}), 500


# GET VENDOR RATING (Get average rating and reviews for a vendor)
@app.route("/get_vendor_rating/<vendor_id>", methods=["GET"])
def get_vendor_rating(vendor_id):
    try:
        ratings = list(ratings_col.find({"vendor_id": vendor_id}).sort("timestamp", -1))
        
        if not ratings:
            return jsonify({
                "average_rating": 0,
                "total_ratings": 0,
                "reviews": []
            })
        
        average_rating = sum(r["rating"] for r in ratings) / len(ratings)
        
        # Only include reviews from customers who have a valid customer_name
        reviews = [
            {
                "customer_name": r.get("customer_name"),
                "rating": r["rating"],
                "review": r.get("review", ""),
                "timestamp": r.get("timestamp", "").isoformat() if isinstance(r.get("timestamp"), datetime) else ""
            }
            for r in ratings
            if r.get("customer_name") and r.get("customer_name").strip()  # Only show if customer_name exists and is not empty
        ]
        
        return jsonify({
            "average_rating": round(average_rating, 1),
            "total_ratings": len(ratings),
            "reviews": reviews
        })
    
    except Exception as e:
        print(f"✗ Error fetching ratings: {str(e)}")
        return jsonify({"error": str(e)}), 500


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# Dictionary to map user_id to socket IDs
user_socket_map = {}

@socketio.on('connect')
def handle_connect():
    print(f"✓ New WebSocket connection: {request.sid}")

@socketio.on('register_user')
def handle_register_user(data):
    user_id = data.get('user_id')
    if user_id:
        user_socket_map[user_id] = request.sid
        join_room(user_id)
        print(f"✓ User {user_id} registered with socket {request.sid} and joined room {user_id}")
        return {"status": "registered", "user_id": user_id}
    else:
        print(f"✗ Register user called without user_id")
        return {"status": "error", "message": "user_id required"}

# EDIT VENDOR PROFILE
@app.route("/edit_vendor_profile", methods=["GET", "POST"])
def edit_vendor_profile():
    if "user_id" not in session or session.get("role") != "vendor":
        return redirect(url_for("login"))

    vendor = vendors_col.find_one({"user_id": session["user_id"]})
    
    if not vendor:
        return redirect(url_for("login"))

    if request.method == "POST":
        try:
            # Editable fields (treat empty inputs as "no change")
            area = request.form.get("area", "").strip()
            state = request.form.get("state", "").strip()
            city = request.form.get("city", "").strip()
            pincode = request.form.get("pincode", "").strip()
            phone = request.form.get("phone", "").strip()
            password = request.form.get("password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()

            # Determine final values: use provided values or fall back to existing vendor values
            final_area = area if area else vendor.get("area", "")
            final_state = state if state else vendor.get("state", "")
            final_city = city if city else vendor.get("city", "")
            final_pincode = pincode if pincode else vendor.get("pincode", "")
            final_phone = phone if phone else vendor.get("phone", "")

            # Validate required final location fields and phone
            if not all([final_area, final_state, final_city, final_pincode, final_phone]):
                return "Please fill all required fields"

            # Validate phone only when provided or when final differs
            if phone and not is_valid_phone(final_phone):
                return "Invalid phone number. Please enter a valid 10-digit Indian phone number starting with 6, 7, 8, or 9"

            # Ensure phone uniqueness only if changed
            if final_phone != vendor.get("phone", ""):
                existing_user = users_col.find_one({"phone": final_phone})
                if existing_user and str(existing_user.get("_id")) != session.get("user_id"):
                    return "Phone number already registered"

            # Process items
            item_names = request.form.getlist("item_name[]")
            item_prices = request.form.getlist("item_price[]")
            items = []
            for idx, item_name in enumerate(item_names):
                item_name = item_name.strip()
                item_price = item_prices[idx].strip() if idx < len(item_prices) else ""
                if item_name and item_price:
                    items.append({
                        "_id": ObjectId(),
                        "name": item_name,
                        "price": item_price,
                        "photo": ""  # Keep existing photo
                    })

            # If no items were submitted, keep existing items
            if not items:
                items = vendor.get("items", [])

            # Process localities from form (if any), otherwise keep existing
            locality_names = request.form.getlist("locality[]")
            localities = []
            for locality_name in locality_names:
                ln = locality_name.strip()
                if ln:
                    localities.append({"_id": ObjectId(), "name": ln})

            if not localities:
                localities = vendor.get("localities", [])

            # Prepare update payload using final values
            vendor_update = {
                "area": final_area,
                "state": final_state,
                "city": final_city,
                "pincode": final_pincode,
                "items": items,
                "localities": localities,
                "phone": final_phone
            }

            vendors_col.update_one(
                {"user_id": session["user_id"]},
                {"$set": vendor_update}
            )

            # Update phone in users collection (if changed)
            try:
                users_col.update_one(
                    {"_id": ObjectId(session["user_id"])},
                    {"$set": {"phone": final_phone}}
                )
            except Exception:
                pass

            # If password fields provided, validate and update users collection
            if password or confirm_password:
                if not password or not confirm_password:
                    return "Please fill both password fields"
                if password != confirm_password:
                    return "Passwords do not match"
                if len(password) < 6:
                    return "Password must be at least 6 characters long"
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                users_col.update_one(
                    {"_id": ObjectId(session["user_id"])},
                    {"$set": {"password": hashed_password}}
                )

            print(f"✓ Vendor profile updated: {session['user_id']}")
            return redirect(url_for("vendor_home"))

        except Exception as e:
            print(f"✗ Vendor Profile Update Error: {str(e)}")
            return f"Update failed: {str(e)}"

    return render_template("edit_vendor_profile.html", vendor=vendor, items=vendor.get("items", []))

# EDIT CUSTOMER PROFILE
@app.route("/edit_customer_profile", methods=["GET", "POST"])
def edit_customer_profile():
    if "user_id" not in session or session.get("role") != "customer":
        return redirect(url_for("login"))

    customer = customers_col.find_one({"user_id": session["user_id"]})
    
    if not customer:
        return redirect(url_for("login"))

    if request.method == "POST":
        try:
            # Only editable fields
            state = request.form.get("state", "").strip()
            city = request.form.get("city", "").strip()
            house_no = request.form.get("house_no", "").strip()
            locality = request.form.get("locality", "").strip()
            area = request.form.get("area", "").strip()
            pincode = request.form.get("pincode", "").strip()
            phone = request.form.get("phone", "").strip()
            password = request.form.get("password", "").strip()
            confirm_password = request.form.get("confirm_password", "").strip()
            
            # Validate required fields (names and aadhar remain read-only)
            if not all([state, city, locality, area, phone]):
                return "Please fill all required fields"

            # Validate phone
            if not is_valid_phone(phone):
                return "Invalid phone number. Please enter a valid 10-digit Indian phone number starting with 6, 7, 8, or 9"

            # Ensure phone uniqueness (allow keeping same phone)
            existing_user = users_col.find_one({"phone": phone})
            if existing_user and str(existing_user.get("_id")) != session.get("user_id"):
                return "Phone number already registered"

            # Check if user wants to change password
            # Build update payload for customer and also update the computed address
            address = f"{house_no}, {locality}, {area}, {city}, {state}, {pincode}".replace(", , ", ", ")
            address = address.strip().strip(',')

            update_data = {
                "state": state,
                "city": city,
                "house_no": house_no,
                "locality": locality,
                "area": area,
                "pincode": pincode,
                "address": address,
                "phone": phone
            }

            # Check if user wants to change password
            if password or confirm_password:
                # If password fields are filled, validate them
                if not password or not confirm_password:
                    return "Please fill both password fields"
                
                if password != confirm_password:
                    return "Passwords do not match"
                
                if len(password) < 6:
                    return "Password must be at least 6 characters long"
                
                # Hash new password
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                
                # Update password in users collection
                users_col.update_one(
                    {"_id": ObjectId(session["user_id"]) if isinstance(session["user_id"], str) else ObjectId(session["user_id"])},
                    {"$set": {"password": hashed_password}}
                )

            # Update phone in users collection (if changed)
            try:
                users_col.update_one(
                    {"_id": ObjectId(session["user_id"])},
                    {"$set": {"phone": phone}}
                )
            except Exception:
                # Non-fatal: continue to update customer record even if users_col update fails
                pass

            # Update customers collection with editable fields
            customers_col.update_one(
                {"user_id": session["user_id"]},
                {"$set": update_data}
            )

            print(f"✓ Customer profile updated: {session['user_id']}")
            return redirect(url_for("customer_home"))

        except Exception as e:
            print(f"✗ Customer Profile Update Error: {str(e)}")
            return f"Update failed: {str(e)}"

    return render_template("edit_customer_profile.html", customer=customer)

@socketio.on('disconnect')
def handle_disconnect():
    # Find and remove user from map
    for user_id, sid in list(user_socket_map.items()):
        if sid == request.sid:
            del user_socket_map[user_id]
            leave_room(user_id)
            print(f"✗ User {user_id} disconnected")
            break

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", debug=True)
