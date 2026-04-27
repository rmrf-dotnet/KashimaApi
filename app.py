import os
import secrets
import hashlib
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    jsonify,
    flash,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

app = Flask(__name__)
app.config["SECRET_KEY"] = secrets.token_hex(32)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///kashima.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    is_active = db.Column(db.Boolean, default=True)
    api_keys = db.relationship(
        "ApiKey", backref="user", lazy=True, cascade="all, delete-orphan"
    )


class ApiKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    key = db.Column(db.String(64), unique=True, nullable=False)
    name = db.Column(db.String(50), default="Default")
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    last_used = db.Column(db.DateTime, nullable=True)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/forks")
def forks():
    return render_template("forks.html")


@app.route("/forks/<model>")
def fork_detail(model):
    return render_template("fork_detail.html", model=model)


@app.route("/shocks")
def shocks():
    return render_template("shocks.html")


@app.route("/shocks/<model>")
def shock_detail(model):
    return render_template("shock_detail.html", model=model)


@app.route("/droppers")
def droppers():
    return render_template("droppers.html")


@app.route("/droppers/<model>")
def dropper_detail(model):
    return render_template("dropper_detail.html", model=model)


@app.route("/upload_images")
def upload_images():
    return render_template("upload_images.html")


DOCS_PAGES = {
    "index": {"title": "Welcome to Kashima Research API", "icon": "home"},
    "why_exists": {"title": "Why This API Exists", "icon": "question"},
    "problems_solved": {"title": "Problems We Solve", "icon": "solution"},
    "use_cases": {"title": "Use Cases", "icon": "use"},
    "benefits": {"title": "Benefits & Value", "icon": "benefit"},
    "who_for": {"title": "Who Is This For", "icon": "users"},
    "comparison": {"title": "Compare Parts", "icon": "compare"},
    "buying_guide": {"title": "Buying Guide", "icon": "cart"},
    "technical_specs": {"title": "Understanding Specs", "icon": "specs"},
    "fork_guide": {"title": "Fork Selection", "icon": "fork"},
    "shock_guide": {"title": "Shock Selection", "icon": "shock"},
    "dropper_guide": {"title": "Dropper Selection", "icon": "dropper"},
    "getting_started": {"title": "Getting Started", "icon": "start"},
    "authentication": {"title": "Authentication", "icon": "auth"},
    "endpoints": {"title": "API Endpoints", "icon": "endpoint"},
    "response_format": {"title": "Response Format", "icon": "response"},
    "error_handling": {"title": "Error Handling", "icon": "error"},
    "rate_limits": {"title": "Rate Limits", "icon": "rate"},
    "pricing": {"title": "Pricing & Plans", "icon": "price"},
    "faq": {"title": "FAQ", "icon": "faq"},
    "glossary": {"title": "Glossary", "icon": "book"},
    "terminology": {"title": "Mountain Bike Terms", "icon": "term"},
    "kashima_coat": {"title": "What is Kashima?", "icon": "gold"},
    "series_explained": {"title": "Factory vs Performance", "icon": "series"},
    "travel_explained": {"title": "Understanding Travel", "icon": "travel"},
    "integration": {"title": "Integration Guide", "icon": "integrate"},
    "embed_examples": {"title": "Embed Examples", "icon": "code"},
    "support": {"title": "Support", "icon": "support"},
    "contact": {"title": "Contact Us", "icon": "contact"},
    "changelog": {"title": "Changelog", "icon": "history"},
}


@app.route("/api_docs")
def api_docs():
    api_key = session.get("api_key")
    return render_template("api_docs/index.html", pages=DOCS_PAGES, api_key=api_key)


@app.route("/api_docs/<page>")
def api_docs_page(page):
    api_key = session.get("api_key")
    if page not in DOCS_PAGES:
        page = "index"
    return render_template(
        f"api_docs/{page}.html", pages=DOCS_PAGES, current_page=page, api_key=api_key
    )


@app.route("/account", methods=["GET", "POST"])
def account():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    api_keys = ApiKey.query.filter_by(user_id=user.id).all()
    return render_template("account.html", user=user, api_keys=api_keys)


@app.route("/account/save", methods=["POST"])
def save_account():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])

    new_username = request.form.get("username", "").strip()
    new_email = request.form.get("email", "").strip()
    new_password = request.form.get("password", "").strip()

    changed = False

    if new_username and new_username != user.username:
        if User.query.filter_by(username=new_username).first():
            flash("Username already taken", "error")
        else:
            user.username = new_username
            session["username"] = new_username
            changed = True

    if new_email and new_email != user.email:
        if User.query.filter_by(email=new_email).first():
            flash("Email already taken", "error")
        else:
            user.email = new_email
            changed = True

    if new_password:
        user.password_hash = generate_password_hash(new_password)
        changed = True

    if changed:
        db.session.commit()
        flash("Account updated successfully!", "success")

    return redirect(url_for("account"))


@app.route("/api-keys/create", methods=["POST"])
def create_api_key():
    if "user_id" not in session:
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    key_name = request.form.get("name", "").strip() or "Key"

    existing_count = ApiKey.query.filter_by(user_id=user.id).count()
    if existing_count >= 5:
        flash("Maximum 5 API keys allowed", "error")
        return redirect(url_for("account"))

    new_key = ApiKey(
        user_id=user.id, key=secrets.token_hex(32), name=key_name[:50], is_active=True
    )
    db.session.add(new_key)
    db.session.commit()

    session["api_key"] = new_key.key
    flash(f"API key '{new_key.name}' created!", "success")
    return redirect(url_for("account"))


@app.route("/api-keys/<int:key_id>/toggle", methods=["POST"])
def toggle_api_key(key_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    api_key = ApiKey.query.filter_by(id=key_id, user_id=session["user_id"]).first()
    if not api_key:
        flash("API key not found", "error")
        return redirect(url_for("account"))

    api_key.is_active = not api_key.is_active
    db.session.commit()

    status = "activated" if api_key.is_active else "deactivated"
    flash(f"API key '{api_key.name}' {status}", "success")
    return redirect(url_for("account"))


@app.route("/api-keys/<int:key_id>/delete", methods=["POST"])
def delete_api_key(key_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    api_key = ApiKey.query.filter_by(id=key_id, user_id=session["user_id"]).first()
    if not api_key:
        flash("API key not found", "error")
        return redirect(url_for("account"))

    key_name = api_key.name
    db.session.delete(api_key)
    db.session.commit()

    if session.get("api_key") == api_key.key:
        first_key = ApiKey.query.filter_by(user_id=session["user_id"]).first()
        session["api_key"] = first_key.key if first_key else None

    flash(f"API key '{key_name}' deleted", "success")
    return redirect(url_for("account"))


@app.route("/api-keys/<int:key_id>/set-active", methods=["POST"])
def set_active_api_key(key_id):
    if "user_id" not in session:
        return redirect(url_for("login"))

    api_key = ApiKey.query.filter_by(id=key_id, user_id=session["user_id"]).first()
    if not api_key:
        flash("API key not found", "error")
        return redirect(url_for("account"))

    if not api_key.is_active:
        api_key.is_active = True
        db.session.commit()

    session["api_key"] = api_key.key
    flash(f"Using API key '{api_key.name}'", "success")
    return redirect(url_for("account"))


@app.route("/search")
def search():
    query = request.args.get("q", "").lower()
    category = request.args.get("category", "all")
    series = request.args.get("series", "all")
    travel_min = request.args.get("travel_min", "")
    travel_max = request.args.get("travel_max", "")
    wheel_size = request.args.get("wheel_size", "all")
    stanchion = request.args.get("stanchion", "all")
    spring_type = request.args.get("spring_type", "all")

    all_parts = get_all_parts()
    results = []

    if (
        query
        or category != "all"
        or series != "all"
        or wheel_size != "all"
        or stanchion != "all"
        or spring_type != "all"
        or travel_min
        or travel_max
    ):
        for cat_name, cat_data in all_parts.items():
            if category != "all" and cat_name != category:
                continue

            for model, part in cat_data.get("models", {}).items():
                include = True

                if query:
                    search_text = f"{part.get('name', '')} {part.get('description', '')} {part.get('series', '')} {model}".lower()
                    if query not in search_text:
                        include = False

                if include and series != "all":
                    if part.get("series", "").lower() != series.lower():
                        include = False

                if include and wheel_size != "all":
                    ws = part.get("wheel_size", [])
                    if ws and wheel_size not in ws:
                        include = False

                if include and stanchion != "all":
                    sd = part.get("stanchion_diameter", "")
                    if sd != stanchion:
                        include = False

                if include and spring_type != "all":
                    st = part.get("spring_type", "") or part.get("spring_type", "")
                    if spring_type.lower() not in st.lower():
                        include = False

                if include and (travel_min or travel_max):
                    tr = part.get("travel", [])
                    if tr:
                        tr_vals = [
                            int("".join(c for c in t if c.isdigit())) for t in tr if t
                        ]
                        if travel_min and tr_vals and min(tr_vals) < int(travel_min):
                            include = False
                        if travel_max and tr_vals and max(tr_vals) > int(travel_max):
                            include = False

                if include:
                    results.append(
                        {
                            "category": cat_name,
                            "model": model,
                            "name": part.get("name", model),
                            "series": part.get("series", ""),
                            "description": part.get("description", ""),
                            "travel": part.get("travel", []),
                            "wheel_size": part.get("wheel_size", []),
                            "stanchion_diameter": part.get("stanchion_diameter", ""),
                            "weight": part.get("weight", ""),
                            "intended_use": part.get("intended_use", ""),
                            "url": f"/{cat_name}/{model}",
                        }
                    )

    filters = {
        "categories": ["forks", "shocks", "droppers"],
        "series": ["Factory", "Performance", "Performance Elite"],
        "wheel_sizes": ['29"', '27.5"', '26"'],
        "stanchions": ["32mm", "34mm", "36mm", "38mm", "40mm"],
        "spring_types": ["Air", "Coil"],
    }

    return render_template(
        "search.html",
        results=results,
        query=query,
        filters=filters,
        category=category,
        series=series,
        wheel_size=wheel_size,
        stanchion=stanchion,
        spring_type=spring_type,
        travel_min=travel_min,
        travel_max=travel_max,
    )


@app.route("/api/search/suggest")
def api_search_suggest():
    q = request.args.get("q", "").lower()
    if not q or len(q) < 2:
        return jsonify([])

    all_parts = get_all_parts()
    suggestions = []

    for cat_name, cat_data in all_parts.items():
        for model, part in cat_data.get("models", {}).items():
            name = part.get("name", model).lower()
            desc = part.get("description", "").lower()
            series = part.get("series", "").lower()

            if q in name or q in desc or q in series or q in model.lower():
                suggestions.append(
                    {
                        "name": part.get("name", model),
                        "model": model,
                        "category": cat_name.replace("_", " ").title(),
                        "series": part.get("series", ""),
                        "url": f"/{cat_name}/{model}",
                    }
                )

    suggestions = suggestions[:10]
    return jsonify(suggestions)


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("account"))

    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")

        if User.query.filter_by(username=username).first():
            flash("Username already exists", "error")
            return redirect(url_for("register"))

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "error")
            return redirect(url_for("register"))

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        default_key = ApiKey(
            user_id=user.id, key=secrets.token_hex(32), name="Default", is_active=True
        )
        db.session.add(default_key)
        db.session.commit()

        session["user_id"] = user.id
        session["username"] = user.username
        session["api_key"] = default_key.key

        flash("Account created! Your default API key has been generated.", "success")
        return redirect(url_for("account"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("account"))

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            active_key = ApiKey.query.filter_by(user_id=user.id, is_active=True).first()
            session["user_id"] = user.id
            session["username"] = user.username
            session["api_key"] = active_key.key if active_key else None
            return redirect(url_for("account"))

        flash("Invalid credentials", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/regenerate-api-key")
def regenerate_api_key():
    if "user_id" not in session:
        flash("Please login first", "error")
        return redirect(url_for("login"))

    user = User.query.get(session["user_id"])
    user.api_key = secrets.token_hex(32)
    db.session.commit()
    session["api_key"] = user.api_key

    flash("New API key generated: " + user.api_key, "success")
    return redirect(url_for("api_docs"))


@app.route("/api/v1/parts")
def api_parts():
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")

    if not api_key:
        return jsonify({"error": "API key required"}), 401

    api_key_obj = ApiKey.query.filter_by(key=api_key, is_active=True).first()
    if not api_key_obj:
        return jsonify({"error": "Invalid API key"}), 401

    user = api_key_obj.user
    if not user.is_active:
        return jsonify({"error": "Account disabled"}), 401

    category = request.args.get("category")

    parts = get_all_parts()

    if category:
        parts = {k: v for k, v in parts.items() if v.get("category") == category}

    return jsonify(parts)


@app.route("/api/v1/parts/<category>/<model>")
def api_part_detail(category, model):
    api_key = request.headers.get("X-API-Key") or request.args.get("api_key")

    if not api_key:
        return jsonify({"error": "API key required"}), 401

    user = User.query.filter_by(api_key=api_key).first()
    if not user or not user.is_active:
        return jsonify({"error": "Invalid API key"}), 401

    parts = get_all_parts()

    if category not in parts:
        return jsonify({"error": "Category not found"}), 404

    if model not in parts[category]["models"]:
        return jsonify({"error": "Model not found"}), 404

    return jsonify(parts[category]["models"][model])


def get_all_parts():
    return {
        "forks": {
            "category": "forks",
            "models": {
                "32_sc": {
                    "name": "32 SC (Step-Cast)",
                    "series": "Factory",
                    "stanchion_diameter": "32mm",
                    "travel": ["100mm"],
                    "wheel_size": ['29"'],
                    "axle": "Kabolt SL 15x110mm (Boost)",
                    "offset_rake": "44mm",
                    "steerer": '1.5" Tapered',
                    "crown": "58mm",
                    "spring_type": "FLOAT EVOL air spring",
                    "damper": "GRIP SL",
                    "damper_controls": "3-Position Adjust (Open/Medium/Firm)",
                    "finish": "Kashima Coat",
                    "rotor_size": "160mm Direct Post Mount, up to 180mm",
                    "max_tire": '2.4"',
                    "weight": '1,276g (Factory, 29", GRIP SL)',
                    "adjustments": {
                        "low_speed_compression": "3 positions (Open/Medium/Firm)",
                        "low_speed_rebound": "17 clicks",
                        "air_pressure": "Adjustable via Schrader valve",
                    },
                    "intended_use": "Cross-Country / Marathon Racing",
                    "model_years": "2016-2026",
                    "colors": ["Shiny Black", "Shiny Orange"],
                    "photos": [
                        "/static/images/forks/32-sc-1.jpg",
                        "/static/images/forks/32-sc-2.jpg",
                        "/static/images/forks/32-sc-3.jpg",
                    ],
                },
                "34_sc": {
                    "name": "34 SC (Step-Cast)",
                    "series": "Factory",
                    "stanchion_diameter": "34mm",
                    "travel": ["100mm", "120mm"],
                    "wheel_size": ['29"'],
                    "axle": "Kabolt SL 15x110mm (Boost)",
                    "offset_rake": "44mm",
                    "steerer": '1.5" Tapered',
                    "crown": "58mm",
                    "spring_type": "FLOAT EVOL air spring",
                    "damper": "GRIP SL",
                    "damper_controls": "3-Position Adjust",
                    "finish": "Kashima Coat",
                    "rotor_size": "160mm Direct Post Mount, up to 180mm",
                    "max_tire": '2.4"',
                    "air_channels": "Yes (2024+)",
                    "bleeders": "Yes (2024+)",
                    "weight": '1,422g (Factory, 29", 120mm)',
                    "adjustments": {
                        "low_speed_compression": "3 positions (Open/Medium/Firm)",
                        "low_speed_rebound": "17 clicks",
                        "air_pressure": "Adjustable via Schrader valve",
                    },
                    "intended_use": "Cross-Country / Trail",
                    "model_years": "2016-2026",
                    "colors": ["Shiny Black", "Shiny Orange", "Podium Gold"],
                    "photos": [
                        "/static/images/forks/34-sc-1.jpg",
                        "/static/images/forks/34-sc-2.jpg",
                        "/static/images/forks/34-sc-3.jpg",
                    ],
                },
                "36": {
                    "name": "36",
                    "series": "Factory",
                    "stanchion_diameter": "36mm",
                    "travel": ["140mm", "150mm", "160mm"],
                    "wheel_size": ['27.5"', '29"'],
                    "axle": "Kabolt-X 15x110mm (Boost)",
                    "offset_rake": '37mm, 44mm (27.5") / 44mm (29")',
                    "steerer": '1.5" Tapered',
                    "crown": "58mm",
                    "spring_type": "FLOAT EVOL air spring",
                    "damper": "GRIP X2",
                    "damper_controls": "HSC-LSC-HSR-LSR",
                    "finish": "Kashima Coat",
                    "rotor_size": "180mm Direct Post Mount, up to 230mm",
                    "max_tire": '2.6"',
                    "air_channels": "Yes",
                    "bleeders": "Yes",
                    "floating_axle": "Yes",
                    "weight": "1,920g - 1,929g (Factory, 160mm)",
                    "adjustments": {
                        "high_speed_compression": "8 clicks",
                        "low_speed_compression": "18 clicks",
                        "high_speed_rebound": "8 clicks",
                        "low_speed_rebound": "16 clicks",
                    },
                    "intended_use": "All-Mountain / Enduro",
                    "model_years": "2019-2026",
                    "colors": ["Shiny Black", "Shiny Orange", "Podium Gold"],
                    "photos": [
                        "/static/images/forks/36-1.jpg",
                        "/static/images/forks/36-2.jpg",
                        "/static/images/forks/36-3.jpg",
                    ],
                },
                "38": {
                    "name": "38",
                    "series": "Factory",
                    "stanchion_diameter": "38mm",
                    "travel": ["160mm", "170mm", "180mm"],
                    "wheel_size": ['27.5"', '29"'],
                    "axle": "Kabolt-X 15x110mm (Boost)",
                    "offset_rake": "44mm",
                    "steerer": '1.5" Tapered',
                    "crown": "58mm",
                    "spring_type": "FLOAT EVOL air spring",
                    "damper": "GRIP X2",
                    "damper_controls": "HSC-LSC-HSR-LSR",
                    "finish": "Kashima Coat",
                    "rotor_size": "180mm Direct Post Mount (2025), 200mm (2026+), up to 230mm",
                    "max_tire": '2.6"',
                    "air_channels": "Yes",
                    "bleeders": "Yes",
                    "floating_axle": "Yes",
                    "weight": "2,194g (2025), 2,360g (2026/27)",
                    "adjustments": {
                        "high_speed_compression": "8 clicks",
                        "low_speed_compression": "18 clicks",
                        "high_speed_rebound": "8 clicks",
                        "low_speed_rebound": "16 clicks",
                    },
                    "intended_use": "Enduro / Downhill",
                    "model_years": "2020-2027",
                    "colors": ["Shiny Black", "Shiny Orange", "Racing Green LTD"],
                    "photos": [
                        "/static/images/forks/38-1.jpg",
                        "/static/images/forks/38-2.jpg",
                        "/static/images/forks/38-3.jpg",
                    ],
                },
                "40": {
                    "name": "40",
                    "series": "Factory",
                    "stanchion_diameter": "40mm",
                    "travel": ["190mm", "203mm"],
                    "wheel_size": ['27.5"', '29"'],
                    "axle": "20mm Thru-Axle x 110mm",
                    "offset_rake": '48mm (27.5") / 52mm (29")',
                    "steerer": '1.125" Straight',
                    "crown": "Triple clamp / Dual crown",
                    "spring_type": "FLOAT EVOL / FLOAT EVOL GlideCore",
                    "damper": "GRIP X2",
                    "damper_controls": "HSC-LSC-HSR-LSR",
                    "finish": "Kashima Coat",
                    "rotor_size": "203mm Direct Post Mount, up to 230mm",
                    "air_channels": "Yes",
                    "bleeders": "Yes",
                    "floating_axle": "Yes",
                    "weight": '2,745g (27.5", 2025/26), 2,888g (29", 2026/27)',
                    "adjustments": {
                        "high_speed_compression": "8 clicks",
                        "low_speed_compression": "18 clicks",
                        "high_speed_rebound": "8 clicks",
                        "low_speed_rebound": "16 clicks",
                    },
                    "intended_use": "Downhill / World Cup Racing",
                    "model_years": "2013-2027",
                    "colors": ["Shiny Black", "Shiny Orange", "Podium Gold"],
                    "photos": [
                        "/static/images/forks/40-1.jpg",
                        "/static/images/forks/40-2.jpg",
                        "/static/images/forks/40-3.jpg",
                    ],
                },
                "ax": {
                    "name": "AX (Kabolt Axle)",
                    "series": "Factory/Performance",
                    "description": "AX refers to forks equipped with the Kabolt axle system - Fox's lightweight floating thru-axle",
                    "axle_variants": {
                        "kabolt_sl": {
                            "used_on": "32 SC, 34 SC, 34 SL",
                            "weight": "Lightest",
                        },
                        "kabolt": {"used_on": "34, 36, 38", "weight": "Standard"},
                        "kabolt_x": {
                            "used_on": "36, 38 (2024+)",
                            "weight": "Improved stiffness",
                        },
                        "20ta": {"used_on": "40, 49", "weight": "DH specific"},
                    },
                    "features": [
                        "Sleeveless design reducing weight",
                        "Single-sided pinch bolt for easy installation",
                        "Floating design for optimal chassis alignment",
                        "12g less than standard QR axle",
                    ],
                    "intended_use": "Universal upgrade",
                    "photos": [
                        "/static/images/forks/ax-kabolt-1.jpg",
                        "/static/images/forks/ax-kabolt-2.jpg",
                        "/static/images/forks/ax-kabolt-3.jpg",
                    ],
                },
                "49": {
                    "name": "49",
                    "series": "Factory",
                    "stanchion_diameter": "40mm",
                    "travel": ["203mm"],
                    "wheel_size": ['29"'],
                    "axle": "20mm Thru-Axle x 110mm",
                    "offset_rake": "52mm",
                    "steerer": '1.125" Straight',
                    "spring_type": "FLOAT EVOL air spring",
                    "damper": "GRIP2 / GRIP X2",
                    "damper_controls": "HSC-LSC-HSR-LSR",
                    "finish": "Kashima Coat",
                    "rotor_size": "203mm Direct Post Mount",
                    "weight": "~2,980g",
                    "intended_use": "World Cup Downhill Racing",
                    "model_years": "2018-2022 (Discontinued)",
                    "colors": ["Shiny Black"],
                    "status": "Discontinued (replaced by 40)",
                    "photos": [
                        "/static/images/forks/49-1.jpg",
                        "/static/images/forks/49-2.jpg",
                        "/static/images/forks/49-3.jpg",
                    ],
                },
                "live_valve_34": {
                    "name": "Live Valve (34)",
                    "series": "Factory",
                    "base_fork": "34",
                    "system_type": "Electronically controlled automatic suspension",
                    "travel": ["130mm", "140mm"],
                    "wheel_size": ['29"'],
                    "damper": "GRIP X",
                    "features": {
                        "sensor_reading_rate": "400 times per second",
                        "adjustment_rate": "~3ms response",
                        "terrain_detection": "Accelerometers detect terrain changes",
                        "battery_life": "16-20 hours",
                        "charge_time": "1.5-2 hours via micro-USB",
                    },
                    "system_components": {
                        "battery": "72g",
                        "controller_sensors": "104g",
                        "fork_damper": "Included in fork",
                        "total_system_add": "~144g vs traditional",
                    },
                    "intended_use": "Trail / All-Mountain with automatic terrain sensing",
                    "model_years": "2018-2026",
                    "finish": "Kashima Coat",
                    "colors": ["Shiny Black"],
                    "photos": [
                        "/static/images/forks/live-valve-34-1.jpg",
                        "/static/images/forks/live-valve-34-2.jpg",
                        "/static/images/forks/live-valve-34-3.jpg",
                    ],
                },
                "live_valve_36": {
                    "name": "Live Valve (36)",
                    "series": "Factory",
                    "base_fork": "36",
                    "system_type": "Electronically controlled automatic suspension",
                    "travel": ["150mm", "160mm"],
                    "wheel_size": ['27.5"', '29"'],
                    "damper": "GRIP X2",
                    "features": {
                        "sensor_reading_rate": "400 times per second",
                        "adjustment_rate": "~3ms response",
                        "terrain_detection": "Accelerometers detect terrain changes",
                        "battery_life": "16-20 hours",
                        "charge_time": "1.5-2 hours via micro-USB",
                    },
                    "system_components": {
                        "battery": "72g",
                        "controller_sensors": "104g",
                        "fork_damper": "249g (36, 160mm)",
                        "total_system_add": "~144g vs traditional",
                    },
                    "intended_use": "All-Mountain / Enduro with automatic terrain sensing",
                    "model_years": "2018-2026",
                    "finish": "Kashima Coat",
                    "colors": ["Shiny Black"],
                    "photos": [
                        "/static/images/forks/live-valve-36-1.jpg",
                        "/static/images/forks/live-valve-36-2.jpg",
                        "/static/images/forks/live-valve-36-3.jpg",
                    ],
                },
            },
        },
        "shocks": {
            "category": "rear_shocks",
            "models": {
                "float_dps": {
                    "name": "Float DPS Factory",
                    "series": "Factory",
                    "spring_type": "Air (EVOL positive spring)",
                    "air_spring_options": [
                        "EVOL LV (Large Volume)",
                        "EVOL SV (Small Volume)",
                        "Remote compatible",
                    ],
                    "eye_to_eye_imperial": [
                        '6.5" x 1.5"',
                        '7.25" x 1.75"',
                        '7.5" x 2"',
                        '7.875" x 2"',
                        '7.875" x 2.25"',
                    ],
                    "eye_to_eye_metric": [
                        "190x45",
                        "210x50",
                        "210x52.5",
                        "210x55",
                        "230x60",
                        "230x65",
                    ],
                    "trunnion_sizes": ["185x52.5", "185x55", "205x60", "205x62.5"],
                    "stroke_range": '38mm - 65mm (1.5" - 2.25")',
                    "damper_controls": "3-Position Lever, 2-Position Remote, or No Lever",
                    "external_adjustments": {"Rebound Damping": "Available"},
                    "finish": "Kashima Coat (upper tube/body)",
                    "weight": '221g (6.5x1.5", without hardware)',
                    "shaft_diameter": "9mm",
                    "intended_use": "Cross Country / Trail",
                    "model_years": "Current",
                    "max_air_pressure": "350 psi",
                    "photos": [
                        "/static/images/shocks/float-dps-1.jpg",
                        "/static/images/shocks/float-dps-2.jpg",
                        "/static/images/shocks/float-dps-3.jpg",
                    ],
                },
                "float_dpx2": {
                    "name": "Float DPX2 Factory",
                    "series": "Factory",
                    "spring_type": "Air (EVOL positive spring)",
                    "air_spring_options": ["EVOL LV (Large Volume)"],
                    "eye_to_eye_imperial": [
                        '7.25" x 1.75"',
                        '7.5" x 2"',
                        '7.875" x 2"',
                        '7.875" x 2.25"',
                        '8.5" x 2.5"',
                    ],
                    "eye_to_eye_metric": [
                        "185x50",
                        "185x52.5",
                        "185x55",
                        "205x62.5",
                        "205x65",
                        "210x50",
                        "210x52.5",
                        "210x55",
                        "230x60",
                        "230x65",
                    ],
                    "trunnion_sizes": [
                        "185x50",
                        "185x52.5",
                        "185x55",
                        "205x62.5",
                        "205x65",
                    ],
                    "stroke_range": '44mm - 65mm (1.75" - 2.5")',
                    "damper_controls": "3-Position Lever, 2-Position Remote",
                    "external_adjustments": {
                        "Rebound Damping": "Available",
                        "Low-Speed Compression": "Available",
                    },
                    "finish": "Kashima Coat (air sleeve and body)",
                    "weight": '398g (7.5x2.0" typical)',
                    "shaft_diameter": '12.7mm (1/2")',
                    "damper_architecture": "Recirculating oil damper",
                    "intended_use": "Trail / Enduro",
                    "model_years": "2018-2024",
                    "max_air_pressure": "350 psi",
                    "photos": [
                        "/static/images/shocks/float-dpx2-1.jpg",
                        "/static/images/shocks/float-dpx2-2.jpg",
                        "/static/images/shocks/float-dpx2-3.jpg",
                    ],
                },
                "float_x": {
                    "name": "Float X Factory",
                    "series": "Factory",
                    "spring_type": "Air (EVOL LV positive spring)",
                    "reservoir": "Piggyback reservoir",
                    "eye_to_eye_imperial": [
                        '7.875" x 2.0"',
                        '7.875" x 2.25"',
                        '8.5" x 2.5"',
                        '9.5" x 3.0"',
                        '10.5" x 3.5"',
                    ],
                    "eye_to_eye_metric": [
                        "190x45",
                        "210x50",
                        "210x52.5",
                        "210x55",
                        "230x57.5",
                        "230x60",
                        "230x62.5",
                        "230x65",
                    ],
                    "trunnion_sizes": ["185x52.5", "185x55", "205x60", "205x62.5"],
                    "stroke_range": '45mm - 76mm (1.75" - 3.0")',
                    "damper_controls": "2-Position Lever (Open/Firm)",
                    "external_adjustments": {
                        "low_speed_compression": "12 clicks",
                        "low_speed_rebound": "16 clicks",
                        "high_speed_compression": "Available",
                        "high_speed_rebound": "Available",
                    },
                    "finish": "Kashima Coat (body and air sleeve)",
                    "shaft_diameter": '12.7mm (1/2")',
                    "features": [
                        "MCU bottom-out bumper",
                        "Hydraulic top-out",
                        "Numbered LSC adjuster",
                    ],
                    "intended_use": "All-Mountain / Enduro",
                    "model_years": "2022-2025",
                    "adjustability": "4-way (HS/LS compression, HS/LS rebound)",
                    "photos": [
                        "/static/images/shocks/float-x-1.jpg",
                        "/static/images/shocks/float-x-2.jpg",
                        "/static/images/shocks/float-x-3.jpg",
                    ],
                },
                "float_x2": {
                    "name": "Float X2 Factory",
                    "series": "Factory",
                    "spring_type": "Air",
                    "architecture": "Monotube (Pressure Balanced)",
                    "reservoir": "Piggyback",
                    "eye_to_eye_imperial": [
                        '7.875" x 2.0"',
                        '8.5" x 2.5"',
                        '9.5" x 3.0"',
                        '10.5" x 3.5"',
                    ],
                    "eye_to_eye_metric": [
                        "210x50",
                        "210x52.5",
                        "210x55",
                        "230x57.5",
                        "230x60",
                        "230x62.5",
                        "230x65",
                    ],
                    "trunnion_sizes": [
                        "185x50",
                        "185x55",
                        "205x55",
                        "205x60",
                        "205x65",
                        "225x75",
                    ],
                    "stroke_range": '50mm - 89mm (2.0" - 3.5")',
                    "damper_controls": "2-Position Lever (Open/Firm)",
                    "external_adjustments": {
                        "high_speed_compression": "Available",
                        "low_speed_compression": "Available",
                        "high_speed_rebound": "8 clicks (VVC)",
                        "low_speed_rebound": "16 clicks",
                    },
                    "finish": "Kashima Coat",
                    "weight": "708g (210x55mm with 2-pos lever)",
                    "shaft_diameter": '12.7mm (1/2")',
                    "features": [
                        "VVC (Variable Valve Control)",
                        "MCU bottom-out bumper",
                    ],
                    "intended_use": "Enduro / Downhill",
                    "model_years": "2021-2026",
                    "adjustability": "4-way",
                    "max_air_pressure": "300 psi",
                    "photos": [
                        "/static/images/shocks/float-x2-1.jpg",
                        "/static/images/shocks/float-x2-2.jpg",
                        "/static/images/shocks/float-x2-3.jpg",
                    ],
                },
                "dhx": {
                    "name": "DHX Factory",
                    "series": "Factory",
                    "spring_type": "Coil",
                    "reservoir": "Piggyback",
                    "eye_to_eye_imperial": [
                        '7.875" x 2.0"',
                        '7.875" x 2.25"',
                        '8.5" x 2.5"',
                        '8.75" x 2.75"',
                        '9.5" x 3.0"',
                        '10.5" x 3.5"',
                    ],
                    "eye_to_eye_metric": [
                        "190x45",
                        "210x50",
                        "210x52.5",
                        "210x55",
                        "230x57.5",
                        "230x60",
                        "230x62.5",
                        "230x65",
                        "250x75",
                    ],
                    "trunnion_sizes": [
                        "185x50",
                        "185x52.5",
                        "185x55",
                        "205x57.5",
                        "205x60",
                        "205x62.5",
                        "205x65",
                        "225x70",
                    ],
                    "stroke_range": '45mm - 89mm (1.75" - 3.5")',
                    "damper_controls": "2-Position Lever (Open/Firm), HSC/LSC/HSR/LSR",
                    "external_adjustments": {
                        "coil_preload": "Available",
                        "high_speed_compression": "Available",
                        "low_speed_compression": "Available",
                        "high_speed_rebound": "Available",
                        "low_speed_rebound": "Available",
                    },
                    "finish": "Hard Chrome (upper tube)",
                    "shaft_diameter": '12.7mm (1/2")',
                    "features": [
                        "Full diameter spring retainer",
                        "Scuff guard",
                        "VVC high-speed rebound",
                    ],
                    "spring_compatibility": "FOX SLS Coil Springs",
                    "intended_use": "Enduro / Downhill",
                    "model_years": "2020-2024",
                    "adjustability": "4-way",
                    "recommended_sag": "~30% of travel",
                    "photos": [
                        "/static/images/shocks/dhx-1.jpg",
                        "/static/images/shocks/dhx-2.jpg",
                        "/static/images/shocks/dhx-3.jpg",
                    ],
                },
                "dhx2": {
                    "name": "DHX2 Factory",
                    "series": "Factory",
                    "spring_type": "Coil",
                    "architecture": "Monotube",
                    "reservoir": "Reduced length for better frame fit",
                    "eye_to_eye_imperial": [
                        '7.875" x 2.0"',
                        '8.5" x 2.5"',
                        '9.5" x 3.0"',
                        '10.5" x 3.5"',
                    ],
                    "eye_to_eye_metric": [
                        "210x50",
                        "210x55",
                        "230x57.5",
                        "230x60",
                        "230x62.5",
                        "230x65",
                        "250x75",
                    ],
                    "trunnion_sizes": [
                        "185x50",
                        "185x55",
                        "205x60",
                        "205x65",
                        "225x75",
                    ],
                    "stroke_range": '50mm - 89mm (2.0" - 3.5")',
                    "damper_controls": "2-Position Lever (Open/Firm)",
                    "external_adjustments": {
                        "coil_preload": "Detents available",
                        "high_speed_compression": "8 clicks (VVC)",
                        "low_speed_compression": "16 clicks",
                        "high_speed_rebound": "8 clicks (VVC)",
                        "low_speed_rebound": "16 clicks",
                    },
                    "finish": "Hard Chrome / Kashima",
                    "weight": "568g (210x55mm without spring)",
                    "shaft_diameter": '12.7mm (1/2")',
                    "features": [
                        "Spring preload collar with detents",
                        "VVC (Variable Valve Control)",
                        "MCU bumper",
                    ],
                    "spring_compatibility": "FOX SLS Coil Springs",
                    "intended_use": "Enduro / Downhill",
                    "model_years": "2022-2026",
                    "adjustability": "4-way independent",
                    "recommended_sag": "~30% of travel",
                    "max_spring_rate": "500 lbs/in",
                    "photos": [
                        "/static/images/shocks/dhx2-1.jpg",
                        "/static/images/shocks/dhx2-2.jpg",
                        "/static/images/shocks/dhx2-3.jpg",
                    ],
                },
            },
        },
        "droppers": {
            "category": "dropper_posts",
            "models": {
                "transfer": {
                    "name": "Transfer Factory",
                    "series": "Factory",
                    "travel_options": ["120mm", "150mm", "180mm", "210mm", "240mm"],
                    "travel_adjustment": "Adjustable down 25mm in 5mm increments",
                    "diameter_sizes": ["30.9mm", "31.6mm", "34.9mm"],
                    "cable_routing": "Internal only",
                    "lever_type": "Cable remote (Matchmaker, I-spec EV compatible)",
                    "finish": "Kashima Coat on upper stanchion, Anodized Black on lower",
                    "actuation": "Cable Remote with nitrogen gas spring",
                    "weight_30_9mm": {
                        "120mm": "475g",
                        "150mm": "528g",
                        "180mm": "585g",
                        "210mm": "636g",
                    },
                    "weight_31_6mm": {
                        "120mm": "492g",
                        "150mm": "549g",
                        "180mm": "608g",
                        "210mm": "667g",
                        "240mm": "730g",
                    },
                    "weight_34_9mm": {
                        "120mm": "555g",
                        "150mm": "621g",
                        "180mm": "691g",
                        "210mm": "759g",
                        "240mm": "826g",
                    },
                    "minimum_insertion": "~80mm (varies by travel/diameter)",
                    "maximum_insertion": "~295-335mm (varies by travel/diameter)",
                    "total_length": "346-611mm (varies by travel/diameter)",
                    "bushings": "Metal-backed EKONOL (PTFE/Teflon)",
                    "service_interval": "300 hours",
                    "intended_use": "Trail, AM, Enduro",
                    "model_years": "2020-2025",
                    "photos": [
                        "/static/images/droppers/transfer-factory-1.jpg",
                        "/static/images/droppers/transfer-factory-2.jpg",
                        "/static/images/droppers/transfer-factory-3.jpg",
                    ],
                },
                "transfer_sl": {
                    "name": "Transfer SL Factory",
                    "series": "Factory",
                    "travel_options": [
                        "50mm",
                        "70mm",
                        "75mm",
                        "100mm",
                        "125mm",
                        "150mm",
                    ],
                    "travel_style": "2-position (fully up or fully down)",
                    "travel_adjustment": "Indexed (no incremental adjustment)",
                    "diameter_sizes": ["27.2mm", "30.9mm", "31.6mm"],
                    "cable_routing": "Internal only",
                    "lever_type": "Cable remote - lightweight 1x, classic 2x, or drop bar compatible",
                    "finish": "Kashima Coat on upper stanchion, Anodized Black on lower",
                    "actuation": "Mechanical 2-position (spring-based, no hydraulics)",
                    "weight_27_2mm": {"50mm": "327g", "70mm": "338g"},
                    "weight_30_9mm": {"75mm": "342g", "100mm": "347g"},
                    "weight_31_6mm": {
                        "75mm": "352g",
                        "100mm": "359g",
                        "125mm": "432g",
                        "150mm": "437g",
                    },
                    "minimum_insertion": "80mm (all sizes)",
                    "maximum_insertion": "248mm (27.2mm), 225mm (30.9/31.6mm), 275mm (31.6mm XL)",
                    "total_length": "350mm (27.2x50) to 480mm (31.6x150)",
                    "stack_height": "53mm",
                    "hardware": "Titanium bolts (Factory - saves 10g)",
                    "intended_use": "XC, Gravel, Light Trail",
                    "model_years": "2022-2025",
                    "photos": [
                        "/static/images/droppers/transfer-sl-factory-1.jpg",
                        "/static/images/droppers/transfer-sl-factory-2.jpg",
                        "/static/images/droppers/transfer-sl-factory-3.jpg",
                    ],
                },
            },
        },
    }


with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True, port=5000)
