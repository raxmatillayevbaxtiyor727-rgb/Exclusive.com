import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const JSON_HEADERS = {
  "content-type": "application/json; charset=utf-8",
  "cache-control": "no-store"
};

const J = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: JSON_HEADERS
  });

const T = (value, max = 200) =>
  String(value ?? "").trim().slice(0, max);

const b64 = (value) =>
  Buffer.from(value).toString("base64url");

const hmac = (key, data) =>
  crypto.createHmac("sha256", key).update(data).digest("base64url");

const hash = (password, salt) =>
  crypto.scryptSync(password, salt, 64).toString("hex");

const eq = (a, b) => {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
};

const makeToken = (admin) => {
  const payload = b64(JSON.stringify({
    u: admin.user,
    v: admin.v,
    exp: Date.now() + 86400000
  }));

  return payload + "." + hmac(admin.secret, payload);
};

function verifyToken(admin, request) {
  if (!admin) return false;

  const auth = request.headers.get("authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;

  const parts = auth.slice(7).split(".");
  if (parts.length !== 2) return false;

  const [data, signature] = parts;

  if (!eq(signature, hmac(admin.secret, data))) return false;

  try {
    const payload = JSON.parse(
      Buffer.from(data, "base64url").toString("utf8")
    );

    return (
      payload.exp > Date.now() &&
      payload.v === admin.v &&
      payload.u === admin.user
    );
  } catch {
    return false;
  }
}

async function listStore(store) {
  const { blobs } = await store.list();

  const values = await Promise.all(
    blobs.map(blob => store.get(blob.key, { type: "json" }))
  );

  return values.filter(Boolean);
}

async function sendTelegram(text) {
  const token = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) return "not_configured";

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${token}/sendMessage`,
      {
        method: "POST",
        headers: {"content-type": "application/json"},
        body: JSON.stringify({
          chat_id: chatId,
          text
        })
      }
    );

    return response.ok ? "sent" : "failed";
  } catch {
    return "failed";
  }
}

export default async function handler(request) {
  const url = new URL(request.url);

  const route = url.pathname
    .replace(/^\/(\.netlify\/functions\/api|api)\/?/, "")
    .replace(/\/$/, "");

  const method = request.method;

  let body = {};
  if (method === "POST" || method === "PUT") {
    body = await request.json().catch(() => ({}));
  }

  const products = getStore("products");
  const orders = getStore("orders");
  const configStore = getStore("config");
  const auth = getStore("auth");

  const setupKey =
    process.env.SETUP_KEY ||
    process.env.ADMIN_PASSWORD ||
    "";

  try {
    if (route === "health" && method === "GET") {
      let db = "ok";
      let adminExists = false;

      try {
        const admin = await auth.get("admin", {type: "json"});
        adminExists = Boolean(admin);
      } catch (error) {
        db = "xato: " + error.message;
      }

      return J({
        ok: true,
        db,
        adminExists,
        setupKeySet: Boolean(setupKey),
        telegramConfigured: Boolean(
          process.env.TELEGRAM_BOT_TOKEN &&
          process.env.TELEGRAM_CHAT_ID
        )
      });
    }

    const admin = await auth.get("admin", {type: "json"});
    const isAdmin = verifyToken(admin, request);

    const ipSource =
      request.headers.get("x-nf-client-connection-ip") ||
      request.headers.get("x-forwarded-for") ||
      "unknown";

    const ip = crypto
      .createHash("sha256")
      .update(ipSource)
      .digest("hex")
      .slice(0, 24);

    if (route === "setup" && method === "POST") {
      if (admin) {
        return J(
          {error: "Admin hisobi allaqachon yaratilgan"},
          403
        );
      }

      if (!setupKey) {
        return J(
          {error: "Netlify Environment Variables ichida SETUP_KEY o‘rnatilmagan"},
          500
        );
      }

      if (!eq(body.key || "", setupKey)) {
        return J(
          {error: "Sozlash kaliti noto‘g‘ri"},
          401
        );
      }

      const username = T(body.username, 40);
      const password = String(body.password || "");

      if (username.length < 3) {
        return J({error: "Login kamida 3 belgi bo‘lsin"}, 400);
      }

      if (password.length < 10) {
        return J({error: "Parol kamida 10 belgi bo‘lsin"}, 400);
      }

      const salt = crypto.randomBytes(16).toString("hex");

      const newAdmin = {
        user: username,
        salt,
        hash: hash(password, salt),
        secret: crypto.randomBytes(32).toString("hex"),
        v: 1
      };

      await auth.setJSON("admin", newAdmin);

      return J({token: makeToken(newAdmin)});
    }

    if (route === "login" && method === "POST") {
      const rate = await auth.get("rl-" + ip, {type: "json"});

      if (rate?.until && rate.until > Date.now()) {
        return J(
          {error: "Juda ko‘p urinish. 15 daqiqadan keyin qayta urinib ko‘ring"},
          429
        );
      }

      if (!admin) {
        return J(
          {error: "Admin hisobi hali yaratilmagan. Avval hisob yarating"},
          409
        );
      }

      const usernameOk =
        eq(T(body.username, 40), admin.user);

      const passwordOk =
        eq(
          hash(String(body.password || ""), admin.salt),
          admin.hash
        );

      if (!usernameOk || !passwordOk) {
        const attempts = (rate?.n || 0) + 1;

        await auth.setJSON(
          "rl-" + ip,
          attempts >= 5
            ? {n: 0, until: Date.now() + 900000}
            : {n: attempts}
        );

        return J(
          {error: "Login yoki parol noto‘g‘ri"},
          401
        );
      }

      if (rate) {
        await auth.delete("rl-" + ip);
      }

      return J({token: makeToken(admin)});
    }

    if (route === "settings" && method === "GET") {
      const settings =
        await configStore.get("settings", {type: "json"});

      return J(settings || {});
    }

    if (route === "products" && method === "GET") {
      const showAll =
        isAdmin && url.searchParams.get("all") === "1";

      const items = await listStore(products);

      return J(
        items
          .filter(item => showAll || item.visible !== false)
          .sort((a, b) => (a.ts || 0) - (b.ts || 0))
      );
    }

    if (route === "order" && method === "POST") {
      const order = {
        id: "o" + Date.now(),
        ts: Date.now(),
        name: T(body.name, 100),
        phone: T(body.phone, 30),
        tg: T(body.tg, 50),
        car: T(body.car, 80),
        year: T(body.year, 10),
        product: T(body.product, 150),
        price: T(body.price, 40),
        wish: T(body.wish, 300),
        address: T(body.address, 300),
        note: T(body.note, 500)
      };

      if (
        !order.name ||
        !/^[+\d\s()-]{7,20}$/.test(order.phone) ||
        !order.car ||
        !order.year ||
        !order.address ||
        !order.product
      ) {
        return J(
          {error: "Majburiy maydonlarni to‘g‘ri to‘ldiring"},
          400
        );
      }

      await orders.setJSON(order.id, order);

      const telegramResult = await sendTelegram(
        `🛒 Yangi buyurtma
${order.product} (${order.price})
Ism: ${order.name}
Tel: ${order.phone}
Telegram: ${order.tg || "-"}
Avto: ${order.car}, ${order.year}
Istak: ${order.wish || "-"}
Manzil: ${order.address}
Izoh: ${order.note || "-"}`
      );

      return J({
        ok: true,
        saved: true,
        telegram: telegramResult
      });
    }

    if (!isAdmin) {
      return J({error: "Kirish talab qilinadi"}, 401);
    }

    if (route === "password" && method === "PUT") {
      const current = String(body.current || "");
      const next = String(body.next || "");

      if (!eq(hash(current, admin.salt), admin.hash)) {
        return J(
          {error: "Hozirgi parol noto‘g‘ri"},
          403
        );
      }

      if (next.length < 10) {
        return J(
          {error: "Yangi parol kamida 10 belgi bo‘lsin"},
          400
        );
      }

      const salt = crypto.randomBytes(16).toString("hex");

      const updatedAdmin = {
        ...admin,
        salt,
        hash: hash(next, salt),
        v: admin.v + 1
      };

      await auth.setJSON("admin", updatedAdmin);

      return J({token: makeToken(updatedAdmin)});
    }

    if (route === "products" && method === "PUT") {
      const image = String(body.img || "");

      const product = {
        id: T(body.id, 40) || "p" + Date.now(),
        name: T(body.name, 120),
        car: T(body.car, 80),
        cat: T(body.cat, 60),
        price: Math.max(0, Number(body.price) || 0),
        visible: body.visible !== false,
        desc: T(body.desc, 2000),
        img: image,
        ts: Number(body.ts) || Date.now()
      };

      if (!product.name || !product.car) {
        return J(
          {error: "Nomi va avtomobil modeli kerak"},
          400
        );
      }

      if (image.length > 900000) {
        return J(
          {error: "Rasm juda katta. Kichikroq rasm tanlang."},
          413
        );
      }

      if (
        image &&
        !image.startsWith("data:image/") &&
        !/^https:\/\//i.test(image)
      ) {
        return J(
          {error: "Rasm formati noto‘g‘ri"},
          400
        );
      }

      await products.setJSON(product.id, product);

      return J({ok: true, product});
    }

    if (route === "products" && method === "DELETE") {
      const id = T(url.searchParams.get("id"), 40);

      if (!id) {
        return J({error: "Mahsulot ID kerak"}, 400);
      }

      await products.delete(id);

      return J({ok: true});
    }

    if (route === "orders" && method === "GET") {
      const items = await listStore(orders);

      return J(
        items.sort((a, b) => (b.ts || 0) - (a.ts || 0))
      );
    }

    if (route === "settings" && method === "PUT") {
      const settings = {};

      for (const key of [
        "phone",
        "telegram",
        "instagram",
        "delivery",
        "howto"
      ]) {
        settings[key] = T(body[key], 600);
      }

      await configStore.setJSON("settings", settings);

      return J({ok: true});
    }

    return J({error: "Topilmadi"}, 404);

  } catch (error) {
    const message = String(error?.message || error);

    const dbError =
      /blobs|siteid|token|environment|store/i.test(
        String(error?.name || "") + " " + message
      );

    return J(
      {
        error: dbError
          ? "Netlify Blobs bilan ulanishda xato: " + message
          : "Server xatosi: " + message,
        code: dbError ? "db_error" : "server_error"
      },
      dbError ? 503 : 500
    );
  }
}
