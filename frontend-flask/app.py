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
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        phone = request.form["phone"]
        aadhar = request.form["aadhar"]
        
        # Get items (multiple)
        items = []
        for key in request.form.keys():
            if key.startswith("item"):
                item_name = request.form[key]
                if item_name.strip():
                    items.append({"_id": ObjectId(), "name": item_name})

        # Get localities (multiple)
        localities = []
        for key in request.form.keys():
            if key.startswith("locality"):
                locality_data = request.form[key]
                if locality_data.strip():
                    localities.append({"_id": ObjectId(), "name": locality_data})

        area = request.form["area"]
        city = request.form["city"]
        pincode = request.form.get("pincode", "")
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]

        # Validate passwords match (BEFORE hashing)
        if password != confirm_password:
            return "Passwords do not match"

        # Check if phone already exists
        if users_col.find_one({"phone": phone}):
            return "Phone number already registered"

        # Hash password AFTER validation
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

        print(f"Vendor registered: {first_name} {last_name}, Phone: {phone}")
        return redirect(url_for("login"))

    return render_template("vendor_reg.html")

# LOGIN PAGE
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form["phone"]
        password = request.form["password"].encode('utf-8')

        user = users_col.find_one({"phone": phone})
        if user and bcrypt.checkpw(password, user["password"]):
            session["user_id"] = str(user["_id"])
            session["role"] = user["role"]

            if user["role"] == "customer":
                return redirect(url_for("customer_home"))
            else:
                return redirect(url_for("vendor_home"))

        return "Invalid phone or password"

    return render_template("login.html")

# CUSTOMER HOME PAGE
@app.route("/customer_home")
def customer_home():
    if "user_id" not in session or session["role"] != "customer":
        return redirect(url_for("login"))

    customer = customers_col.find_one({"user_id": session["user_id"]})
    vendors = list(vendors_col.find())

    return render_template(
        "customer_home.html",
        customer_name=f"{customer['first_name']} {customer['last_name']}",
        customer_phone=customer["phone"],
        customer_address=customer["address"],
        vendors=[{
            "id": str(v["_id"]),
            "name": f"{v['first_name']} {v['last_name']}",
            "phone": v["phone"],
            "city": v["city"],
            "items": [item["name"] for item in v.get("items", [])]
        } for v in vendors]
    )

# VENDOR HOME PAGE
@app.route("/vendor_home")
def vendor_home():
    if "user_id" not in session or session["role"] != "vendor":
        return redirect(url_for("login"))

    vendor = vendors_col.find_one({"user_id": session["user_id"]})

    return render_template(
        "vendor_home.html",
        vendor_name=f"{vendor['first_name']} {vendor['last_name']}",
        vendor_phone=vendor["phone"],
        items=[{"id": str(i["_id"]), "name": i["name"]} for i in vendor.get("items", [])],
        locations=[{
            "id": str(loc["_id"]),
            "locality": loc.get("name", ""),
            "area": vendor.get("area", ""),
            "city": vendor.get("city", "")
        } for loc in vendor.get("localities", [])]
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
