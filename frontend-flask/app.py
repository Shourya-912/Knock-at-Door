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
 
@app.route("/customer/register", methods=["POST"])
def register_customer():
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

@app.route("/vendor/register", methods=["POST"])
def register_vendor():
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
 
if __name__ == "__main__":
    app.run(debug=True)
