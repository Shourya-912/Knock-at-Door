from flask import Flask, render_template, request
 
app = Flask(__name__)
 
@app.route("/")
def home():
    return render_template("home_splash.html")
 
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Handle login logic here (e.g., authenticate user)
        phone = request.form["phone"]
        password = request.form["password"]
        # yaha backend API ko call karna hoga (Node.js authentication)
        return "Login successful!"  # abhi placeholder
    return render_template("Login.html")

@app.route("/register")
def register():
    return render_template("register.html")
 
@app.route("/customer/register", methods=["GET", "POST"])
def cust_reg(): 
    if request.method == "POST":
        # yaha form data capture hoga
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        phone = request.form["phone"]
        aadhar = request.form["aadhar"]
        # aur baki fields bhi
 
        # TODO: save to database
        return "Customer registered successfully!"
    
    return render_template("cust_reg.html")

@app.route("/customer_home")
def customer_home():
    return render_template("customer_home.html")
 

@app.route("/vendor/register", methods=["GET", "POST"])
def vendor_reg():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        phone = request.form["phone"]
        aadhar = request.form["aadhar"]
        items = request.form.getlist("item_extra[]")
        localities = request.form.getlist("locality_extra[]")
        # TODO: Save to DB
        return "Vendor registered successfully!"
    
    return render_template("vendor_reg.html")

@app.route("/vendor/home")
def vendor_home():
    vendor_data = {
        'name': 'Vendor Name',
        'phone': '9876543210'
    }
    
    locations = [
        {'id': 1, 'locality': 'Society A', 'area': 'Downtown', 'city': 'Bhopal'},
        {'id': 2, 'locality': 'Society B', 'area': 'Midtown', 'city': 'Bhopal'},
        {'id': 3, 'locality': 'Society C', 'area': 'Uptown', 'city': 'Bhopal'}
    ]
    
    items = [
        {'id': 1, 'name': 'Plastic'},
        {'id': 2, 'name': 'Paper'},
        {'id': 3, 'name': 'Glass'}
    ]
    
    return render_template('vendor_home.html',
                         vendor_name=vendor_data['name'],
                         vendor_phone=vendor_data['phone'],
                         locations=locations,
                         items=items)
 
if __name__ == "__main__":
    app.run(host = '0.0.0.0', port = 5000, debug=True)
