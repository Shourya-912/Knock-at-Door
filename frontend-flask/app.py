from flask import Flask, render_template, request, redirect, url_for, session
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import bcrypt

app = Flask(__name__)
app.secret_key = "shourya_secret"

# MongoDB Config
app.config["MONGO_URI"] = "mongodb+srv://shourchourasia912:Knock912@cluster0.k07ix.mongodb.net/knockatdoor?retryWrites=true&w=majority"
mongo = PyMongo(app)

users_col = mongo.db.users
vendors_col = mongo.db.vendors
customers_col = mongo.db.customers

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
        state = request.form.get("state", "")
        pincode = request.form.get("pincode", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Validate required fields
        if not all([first_name, last_name, phone, locality, state, password, confirm_password]):
            return "Please fill all required fields"

        # Validate passwords match
        if password != confirm_password:
            return "Passwords do not match"

        # Check if phone already exists
        if users_col.find_one({"phone": phone}):
            return "Phone number already registered"

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create full address
        address = f"{house_no}, {locality}, {state} {pincode}".replace(", , ", ", ")

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
                "state": state,
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
            city = request.form.get("city", "").strip()
            pincode = request.form.get("pincode", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            # Validate required fields
            if not all([first_name, last_name, phone, aadhar, area, city, password, confirm_password]):
                return "Please fill all required fields"

            # Validate passwords match
            if password != confirm_password:
                return "Passwords do not match"

            # Check if phone already exists
            if users_col.find_one({"phone": phone}):
                return "Phone number already registered"

            # Get items (multiple)
            items = []
            # item1, item2 से शुरू
            for i in range(1, 10):
                item_name = request.form.get(f"item{i}", "").strip()
                if item_name:
                    items.append({"_id": ObjectId(), "name": item_name})
            
            # item_extra[] starts (dynamically added)
            item_extras = request.form.getlist("item_extra[]")
            for item_name in item_extras:
                if item_name.strip():
                    items.append({"_id": ObjectId(), "name": item_name.strip()})

            if not items:
                return "Please add at least one item"

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

    return render_template("Login.html")

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

    vendors = list(vendors_col.find())

    print(f"✓ Customer Home loaded: {customer['first_name']} {customer['last_name']}")

    # Format vendors properly
    vendor_list = []
    for v in vendors:
        vendor_items = []
        if "items" in v and isinstance(v["items"], list):
            vendor_items = [item["name"] for item in v["items"]]
        
        vendor_list.append({
            "id": str(v["_id"]),
            "name": f"{v['first_name']} {v['last_name']}",
            "phone": v["phone"],
            "city": v.get("city", ""),
            "vendor_items": vendor_items  # Change name to avoid conflict
        })

    return render_template(
        "customer_home.html",
        customer_name=f"{customer['first_name']} {customer['last_name']}",
        customer_phone=customer["phone"],
        customer_address=customer.get("address", ""),
        vendors=vendor_list
    )    

# VENDOR HOME PAGE
@app.route("/vendor_home")
def vendor_home():
    if "user_id" not in session or session.get("role") != "vendor":
        return redirect(url_for("login"))

    vendor = vendors_col.find_one({"user_id": session["user_id"]})
    
    if not vendor:
        return redirect(url_for("login"))

    # Items को properly format करो
    items = [{"id": str(i["_id"]), "name": i["name"]} for i in vendor.get("items", [])]
    
    # Locations को properly format करो
    locations = []
    for loc in vendor.get("localities", []):
        locations.append({
            "id": str(loc["_id"]),
            "locality": loc.get("name", ""),
            "area": vendor.get("area", ""),
            "city": vendor.get("city", "")
        })

    print(f"✓ Vendor Home loaded: {vendor['first_name']} {vendor['last_name']}")
    print(f"  Items: {[item['name'] for item in items]}")
    print(f"  Localities: {[loc['locality'] for loc in locations]}")

    return render_template(
        "vendor_home.html",
        vendor_name=f"{vendor['first_name']} {vendor['last_name']}",
        vendor_phone=vendor["phone"],
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

# SEND ALERT (Vendor)
@app.route("/send_alert/<loc_id>", methods=["POST"])
def send_alert(loc_id):
    print(f"Alert sent from vendor for location: {loc_id}")
    return {"message": "Alert sent successfully"}

# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
