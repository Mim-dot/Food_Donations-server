const express = require("express");
const cors = require("cors");

const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");

require("dotenv").config();
const stripe = require("stripe")(process.env.PAYMENT_GETWAY_KEY);
const admin = require("firebase-admin");
const serviceAccount = require("./serviceAccount.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const app = express();
const port = process.env.PORT || 7000;

// Middleware
app.use(cors());
app.use(express.json());
app.param("id", (req, res, next, id) => {
  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid ID format" });
    }
    req.objectId = new ObjectId(id);
    next();
  } catch (error) {
    console.error("ID conversion error:", error);
    res.status(400).json({ error: "Invalid ID format" });
  }
});

// MongoDB Connection

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@mim.zblfuks.mongodb.net/?retryWrites=true&w=majority&appName=Mim`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});
async function run() {
  try {
    // Connect the client to the server	(optional starting in v4.7)
    //await client.connect();
    const donationCollection = client.db("donationdb").collection("donations");
    const usersCollection = client.db("donationdb").collection("loggedUser");
    const charityCollection = client.db("donationdb").collection("charity");
    const paymentsCollection = client.db("donationdb").collection("payments");
    const favoritesCollection = client.db("donationdb").collection("favorites");
    const reviewsCollection = client.db("donationdb").collection("reviews");
    const donationRequestsCollection = client
      .db("donationdb")
      .collection("donationRequests");

    //-------------verify--------------
    const verifyFirebaseToken = async (req, res, next) => {
      const authHeader = req.headers.authorization;

      if (!authHeader?.startsWith("Bearer ")) {
        return res
          .status(401)
          .json({ error: "Unauthorized - No token provided" });
      }

      const idToken = authHeader.split(" ")[1];

      try {
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        // Find the user in MongoDB by email
        const userRecord = await usersCollection.findOne({
          email: decodedToken.email,
        });

        if (!userRecord) {
          return res.status(404).json({ error: "User not found in DB" });
        }
        req.user = {
          uid: decodedToken.uid,
          email: decodedToken.email,
          role: userRecord.role || "user", // use role from DB
        };
        // console.log("Verified user:", req.user);
        next();
      } catch (error) {
        console.error("Firebase token verification error:", error);
        res.status(403).json({ error: "Invalid or expired token" });
      }
    };
    const verifyAdmin = async (req, res, next) => {
      const email = req.user?.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== "admin") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };
    const verifyCharity = async (req, res, next) => {
      const email = req.user?.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== "charity") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };
    const verifyRestaurant = async (req, res, next) => {
      const email = req.user?.email;
      const query = { email };
      const user = await usersCollection.findOne(query);
      if (!user || user.role !== "restaurant") {
        return res.status(403).send({ message: "forbidden access" });
      }
      next();
    };
    //-----------------register------------------
    app.post("/users", async (req, res) => {
      try {
        const user = req.body;

        // Validate required fields
        if (!user.email || !user.uid) {
          return res.status(400).json({
            success: false,
            message: "Email and UID are required",
          });
        }

        // Check for existing user
        const existing = await usersCollection.findOne({
          $or: [{ email: user.email }, { uid: user.uid }],
        });

        if (existing) {
          return res.status(200).json({
            success: true,
            message: "User already exists",
            user: existing,
          });
        }

        // Create new user document
        const userData = {
          ...user,
          role: user.role || "user", // consistent role naming
          createdAt: new Date(),
          updatedAt: new Date(),
        };

        const result = await usersCollection.insertOne(userData);

        res.status(201).json({
          success: true,
          message: "User created successfully",
          userId: result.insertedId,
        });
      } catch (error) {
        console.error("Error creating user:", error);
        res.status(500).json({
          success: false,
          message: "Internal server error",
        });
      }
    });
    // ✅ Your backend file (e.g. server.js or index.js)
    app.get("/api/users/:uid", async (req, res) => {
      try {
        const uid = req.params.uid;

        // Try to find by uid
        let user = await usersCollection.findOne({ uid });

        // Fallback: try to find by email (insecure unless validated!)
        if (!user) {
          const email = req.query.email;
          if (email) {
            user = await usersCollection.findOne({ email });
          }
        }

        if (!user) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send(user);
      } catch (error) {
        console.error("Error fetching user:", error);
        res.status(500).send({ message: "Server error" });
      }
    });
    //------------------admin-------------
    app.get("/users/search", verifyAdmin, async (req, res) => {
      const emailQuery = req.query.email;
      if (!emailQuery) {
        return res.status(400).send({ message: "Missing email query" });
      }

      const regex = new RegExp(emailQuery, "i"); // case-insensitive partial match

      try {
        const users = await usersCollection
          .find({ email: { $regex: regex } })
          // .project({ email: 1, createdAt: 1, role: 1 })
          .limit(10)
          .toArray();
        res.send(users);
      } catch (error) {
        console.error("Error searching users", error);
        res.status(500).send({ message: "Error searching users" });
      }
    });
    app.get("/api/users/:email/role", verifyFirebaseToken, async (req, res) => {
      try {
        // console.log("Decoded user in role endpoint:", req.user);
        const email = req.params.email?.toLowerCase();

        if (!email) {
          return res.status(400).send({ message: "email is required" });
        }

        let user = await usersCollection.findOne({ email });

        if (!user) {
          // Auto-create the user
          const newUser = {
            email,
            uid: req.user.uid,
            role: "user",
            createdAt: new Date(),
            updatedAt: new Date(),
          };

          const result = await usersCollection.insertOne(newUser);
          user = newUser;
          //console.log("User auto-created in role endpoint");
        }

        res.send({ role: user.role || "user" });
      } catch (error) {
        console.error("Error in /api/users/:email/role:", error);
        res.status(500).send({ message: "Internal server error" });
      }
    });
    app.get("/api/debug/user/:email", async (req, res) => {
      const email = decodeURIComponent(req.params.email);
      const user = await usersCollection.findOne({
        email: { $regex: new RegExp(`^${email}$`, "i") },
      });
      res.send(user || { error: "Not found", searchedEmail: email });
    });
    // Get all users (admin only)-done
    app.get(
      "/admin/users",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const users = await usersCollection.find().toArray();
          res.send(users);
        } catch (error) {
          console.error("Error fetching users:", error);
          res.status(500).send({ message: "Failed to get users" });
        }
      }
    );
    // Update user role (admin only)-done
    app.patch(
      "/admin/users/:id/role",
      verifyFirebaseToken,
      verifyAdmin,
      async (req, res) => {
        try {
          const id = req.params.id;
          const { role } = req.body;

          if (!ObjectId.isValid(id)) {
            return res.status(400).send({ message: "Invalid ID format" });
          }

          if (!["user", "restaurant", "charity", "admin"].includes(role)) {
            return res.status(400).send({ message: "Invalid role" });
          }

          const result = await usersCollection.updateOne(
            { _id: new ObjectId(id) },
            { $set: { role } }
          );

          if (result.matchedCount === 0) {
            return res.status(404).send({ message: "User not found" });
          }

          res.send({ message: "User role updated successfully" });
        } catch (error) {
          console.error("Error updating user role:", error);
          res.status(500).send({ message: "Failed to update user role" });
        }
      }
    );
    // Delete user (admin only)
    app.delete("/admin/users/:id", async (req, res) => {
      try {
        const id = req.params.id;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        const result = await usersCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).send({ message: "User not found" });
        }

        res.send({ message: "User deleted successfully" });
      } catch (error) {
        console.error("Error deleting user:", error);
        res.status(500).send({ message: "Failed to delete user" });
      }
    });
    // Get all pending charity requests (admin only)
    app.get("/admin/charity-requests",verifyFirebaseToken,verifyAdmin, async (req, res) => {
      try {
        const requests = await charityCollection
          .aggregate([
            {
              $lookup: {
                from: "users",
                localField: "userEmail",
                foreignField: "email",
                as: "user",
              },
            },
            {
              $unwind: {
                path: "$user",
                preserveNullAndEmptyArrays: true,
              },
            },
            {
              $project: {
                _id: 1,
                userName: {
                  $ifNull: [
                    "$user.name",
                    "$user.displayName",
                    "$user.email",
                    "Unknown",
                  ],
                },
                userEmail: "$email",
                organizationName: 1,
                missionStatement: 1,
                transactionId: 1,
                status: 1,
                payment_status: 1,
                submittedAt: 1,
              },
            },
            {
              $sort: { submittedAt: -1 }, // Newest first
            },
          ])
          .toArray();

        res.send(requests);
      } catch (error) {
        console.error("Error fetching charity requests:", error);
        res.status(500).send({ message: "Failed to get charity requests" });
      }
    });
    // Add this to your backend routes
    app.patch("/admin/charity-requests/:id",verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        if (!["Pending", "Approved", "Rejected"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const result = await charityCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Request not found" });
        }

        // If approved, update user role
        if (status === "Approved") {
          const request = await charityCollection.findOne({
            _id: new ObjectId(id),
          });
          if (!request || !request.email) {
            return res
              .status(400)
              .send({ message: "Email not found in request data" });
          }

          const user = await usersCollection.findOne({ email: request.email });
          if (!user) {
            return res.status(404).send({ message: "User not found" });
          }

          await usersCollection.updateOne(
            { email: request.email },
            { $set: { role: "charity" } }
          );
        }

        res.send({ success: true, message: "Status updated successfully" });
      } catch (error) {
        console.error("Error updating request status:", error);
        res.status(500).send({ message: "Failed to update status" });
      }
    });
    // Get all pending donations (admin only)
    app.get("/admin/pending-donations",verifyFirebaseToken, verifyAdmin, async (req, res) => {
      try {
        const donations = await donationCollection
          .find({ status: "Pending" })
          .toArray();
        res.send(donations);
      } catch (error) {
        console.error("Error fetching pending donations:", error);
        res.status(500).send({ message: "Failed to get pending donations" });
      }
    });

    // Update donation status (admin only)
    app.patch("/admin/donations/:id/status", verifyAdmin, async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        if (!["Pending", "Verified", "Rejected"].includes(status)) {
          return res.status(400).send({ message: "Invalid status" });
        }

        const result = await donationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Donation not found" });
        }

        res.send({ message: "Donation status updated successfully" });
      } catch (error) {
        console.error("Error updating donation status:", error);
        res.status(500).send({ message: "Failed to update donation status" });
      }
    });

    // Feature/unfeature a donation (admin only)
    app.patch("/admin/donations/:id/feature", async (req, res) => {
      try {
        const id = req.params.id;
        const { isFeatured } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        const result = await donationCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { isFeatured } }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Donation not found" });
        }

        res.send({ message: "Donation feature status updated successfully" });
      } catch (error) {
        console.error("Error updating donation feature status:", error);
        res.status(500).send({ message: "Failed to update feature status" });
      }
    });
    // GET /donations/featured?limit=4
    app.get("/donations/featured", async (req, res) => {
      try {
        const limit = parseInt(req.query.limit, 10) || 4;

        const featuredDonations = await donationCollection
          .find({ isFeatured: true })
          .limit(limit)
          .toArray();

        res.json(featuredDonations);
      } catch (error) {
        console.error("Error fetching featured donations:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
    //-----------------Add donation---------------
    app.post(
      "/api/donations",
      verifyFirebaseToken,
      verifyRestaurant,
      async (req, res) => {
        try {
          const donation = req.body;
          donation.status = "Pending";
          donation.createdAt = new Date();

          const result = await donationCollection.insertOne(donation);
          res.status(201).json({
            message: "Donation submitted",
            insertedId: result.insertedId,
          });
        } catch (error) {
          console.error("❌ Error adding donation:", error);
          res.status(500).json({ error: "Server error" });
        }
      }
    );

    //-------------------All Donation-------------------
    app.get("/all/donations",verifyFirebaseToken,verifyRestaurant, async (req, res) => {
      const result = await donationCollection.find().toArray();
      res.send(result);
    });
    //----------------my-single---------------
    app.get(
      "/restaurant/donations",
      verifyFirebaseToken,
      verifyRestaurant,
      async (req, res) => {
        const email = req.query.email;
        const query = { restaurantEmail: email };
        const result = await donationCollection.find(query).toArray();
        //console.log("Donations found:", result.length);
        res.send(result);
      }
    );
    //--------------------verify donation-------------
    app.get("/donations/verified", async (req, res) => {
      try {
        const { location, sortBy, order } = req.query;

        const query = { status: "Verified" };

        // 🔍 Add location search (case-insensitive, partial match)
        if (location) {
          query.location = { $regex: location, $options: "i" };
        }

        // 🧾 Sorting
        let sortOptions = {};
        if (sortBy === "quantity") {
          sortOptions.quantity = order === "desc" ? -1 : 1;
        } else if (sortBy === "pickupTime") {
          sortOptions.pickupTime = order === "desc" ? -1 : 1;
        }

        const verifiedDonations = await donationCollection
          .find(query)
          .sort(sortOptions)
          .toArray();

        res.status(200).json(verifiedDonations);
      } catch (error) {
        console.error("Error fetching donations:", error);
        res
          .status(500)
          .json({ message: "Server error while fetching donations" });
      }
    });

    //-----------------delete-----------------
    app.delete("/donations/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await donationCollection.deleteOne(query);
      res.send(result);
    });
    //-------------update-------------
    app.get("/donations/:id", async (req, res) => {
      const id = req.params.id;
      const query = { _id: new ObjectId(id) };
      const result = await donationCollection.findOne(query);
      res.send(result);
    });
    app.put(
      "/donations/:id",
      verifyFirebaseToken,
      verifyRestaurant,
      async (req, res) => {
        const id = req.params.id;
        const newUserData = req.body;
        const query = { _id: new ObjectId(id) };
        const updateDoc = {
          $set: newUserData,
        };
        const result = await donationCollection.updateOne(query, updateDoc);
        res.send(result);
      }
    );
    //---------charity get----------
    app.get("/charity", async (req, res) => {
      try {
        const charities = await charityCollection
          .aggregate([
            {
              $lookup: {
                from: "users", // The collection name where user data is stored
                localField: "email", // Field in charity collection that matches
                foreignField: "email", // Field in users collection
                as: "userInfo", // Array that will contain matched user documents
              },
            },
            {
              $unwind: {
                path: "$userInfo",
                preserveNullAndEmptyArrays: true, // Keep charities even if no user found
              },
            },
            {
              $project: {
                organizationName: 1,
                mission: 1,
                transactionId: 1,
                status: 1,
                email: 1,
                userName: "$userInfo.name", // Extract name from joined user document
                userEmail: "$userInfo.email", // Optional: include if needed
              },
            },
          ])
          .toArray();

        res.send(charities);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });
    // --------- Prevent Duplicate-------
    app.get("/charity/check", async (req, res) => {
      try {
        const email = req.query.email;
        if (!email) {
          return res.status(400).send({ message: "Email is required" });
        }
        const existing = await charityCollection.findOne({
          email,
          status: { $in: ["Pending", "Approved"] },
        });
        res.send({ exists: !!existing });
      } catch (error) {
        console.error("Error in /charity/check:", error);
        res.status(500).send({ message: "Server error" });
      }
    });
    // GET: Get a specific charity by ID
    app.get("/charity/:id", async (req, res) => {
      try {
        const id = req.params.id;
        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }
        const parcel = await charityCollection.findOne({
          _id: new ObjectId(id),
        });

        if (!parcel) {
          return res.status(404).send({ message: "Parcel not found" });
        }

        res.send(parcel);
      } catch (error) {
        console.error("Error fetching parcel:", error);
        res.status(500).send({ message: "Failed to fetch parcel" });
      }
    });
    // 🔹 Modified Save charity role request endpoint
    app.post(
      "/charity",
      verifyFirebaseToken,

      async (req, res) => {
        // console.log("Body received on server:", req.body);
        const {
          email,
          organizationName,
          missionStatement,
          transactionId = "pending",
        } = req.body;

        if (!email || !organizationName || !missionStatement) {
          return res.status(400).send({ message: "Missing required fields" });
        }

        const existing = await charityCollection.findOne({
          email,
          status: { $in: ["Pending", "Approved"] },
        });

        if (existing) {
          return res.status(400).send({ message: "Request already exists 😥" });
        }

        const result = await charityCollection.insertOne({
          email,
          organizationName,
          missionStatement,
          transactionId,
          status: "Pending",
          payment_status: transactionId === "pending" ? "unpaid" : "paid",
          submittedAt: new Date(),
        });

        res.send(result);
      }
    );
    // 🔹 New endpoint to update payment status
    app.put("/charity/payment/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const { transactionId } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        const result = await charityCollection.updateOne(
          { _id: new ObjectId(id) },
          {
            $set: {
              transactionId,
              payment_status: "paid",
              updatedAt: new Date(),
            },
          }
        );

        if (result.matchedCount === 0) {
          return res.status(404).send({ message: "Charity request not found" });
        }

        res.send({ message: "Payment recorded successfully" });
      } catch (error) {
        console.error("Failed to update payment:", error);
        res.status(500).send({ message: "Server error" });
      }
    });
    ///-----------payment-----------
    app.post("/create-payment-intent", async (req, res) => {
      try {
        const { amountInCents, id } = req.body;
        if (!amountInCents) {
          return res.status(400).json({ error: "Amount is required" });
        }
        const paymentIntent = await stripe.paymentIntents.create({
          amount: amountInCents,
          currency: "usd",
          metadata: { order_id: id || "no_id_provided" },
        });
        res.json({ clientSecret: paymentIntent.client_secret });
      } catch (error) {
        console.error("Error creating payment intent:", error);
        res.status(500).json({ error: "Internal server error" });
      }
    });
    // Get all charity requests for a specific user
    app.get("/charity/user", async (req, res) => {
      try {
        const email = req.query.email;
        if (!email || typeof email !== "string") {
          return res.status(400).send({ message: "Email is required" });
        }

        const result = await charityCollection
          .find({ email })
          .sort({ submittedAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching user charity history:", error);
        res.status(500).send({ message: "Server error" });
      }
    });
    //---------------get--------------
    app.get("/payments", async (req, res) => {
      try {
        const userEmail = req.query.email;

        if (!userEmail) {
          return res.status(400).send({ message: "Email is required" });
        }

        const query = { email: userEmail };
        const options = { sort: { paid_at: -1 } };
        const payments = await paymentsCollection
          .find(query, options)
          .toArray();
        res.send(payments);
      } catch (error) {
        console.error("Error fetching payment history:", error);
        res.status(500).send({ message: "Failed to get payments" });
      }
    });
    // Update this endpoint in your server code
    app.get("/charity/user", async (req, res) => {
      try {
        const email = req.query.email;

        // Validate email parameter
        if (!email || typeof email !== "string") {
          return res.status(400).json({
            message: "Valid email is required",
            details: "Email must be a non-empty string",
          });
        }

        // URL decode the email if needed
        const decodedEmail = decodeURIComponent(email);

        const result = await charityCollection
          .find({ email: decodedEmail })
          .sort({ submittedAt: -1 })
          .toArray();

        res.send(result);
      } catch (error) {
        console.error("Error fetching user charity history:", error);
        res.status(500).json({
          message: "Server error",
          error: error.message,
        });
      }
    });
    // In your server code (where you define routes), make sure this comes BEFORE any catch-all routes
    app.post("/payments", async (req, res) => {
      try {
        const { parcelId, email, amount, paymentMethod, transactionId } =
          req.body;

        // Validate required fields
        if (!parcelId || !email || !amount || !transactionId) {
          return res
            .status(400)
            .send({ message: "Missing required payment fields" });
        }

        // 1. First insert payment record
        const paymentDoc = {
          parcelId: new ObjectId(parcelId), // Ensure this is ObjectId if needed
          email,
          amount,
          paymentMethod,
          transactionId,
          paid_at: new Date(),
        };

        //console.log("Inserting payment:", paymentDoc);
        const paymentResult = await paymentsCollection.insertOne(paymentDoc);

        // 2. Then update charity status
        const updateResult = await charityCollection.updateOne(
          { _id: new ObjectId(parcelId) },
          {
            $set: {
              payment_status: "paid",
              transactionId: transactionId,
              updatedAt: new Date(),
            },
          }
        );

        if (updateResult.modifiedCount === 0) {
          console.warn("Charity record not updated, but payment was recorded");
        }

        res.status(201).send({
          message: "Payment recorded successfully",
          paymentId: paymentResult.insertedId,
        });
      } catch (error) {
        console.error("Payment processing failed:", error);
        res.status(500).send({
          message: "Failed to record payment",
          error: error.message,
        });
      }
    });
    // ----------------- Transaction Routes -----------------
    app.get("/transactions", async (req, res) => {
      try {
        const email = req.query.email;
        if (!email)
          return res.status(400).send({ message: "Email is required" });

        const payments = await paymentsCollection.find({ email }).toArray();
        const charityRequests = await charityCollection
          .find({ email })
          .toArray();

        const transactions = payments.map((payment) => {
          const relatedRequest = charityRequests.find(
            (req) => req._id.toString() === payment.parcelId.toString()
          );

          return {
            _id: payment._id,
            transactionId: payment.transactionId,
            amount: payment.amount,
            paymentMethod: payment.paymentMethod,
            date: payment.paid_at,
            status: relatedRequest?.status || "Pending",
            charityRequest: relatedRequest || null,
          };
        });

        res.send(transactions);
      } catch (error) {
        console.error("Error fetching transactions:", error);
        res.status(500).send({ message: "Failed to get transactions" });
      }
    });
    // Add this endpoint to update transaction status
    app.patch("/transactions/:id", async (req, res) => {
      try {
        const id = req.params.id;
        const { status } = req.body;

        if (!ObjectId.isValid(id)) {
          return res.status(400).send({ message: "Invalid ID format" });
        }

        // First update the payment record
        const paymentUpdate = await paymentsCollection.updateOne(
          { _id: new ObjectId(id) },
          { $set: { status } }
        );

        // Then update the associated charity request status
        const payment = await paymentsCollection.findOne({
          _id: new ObjectId(id),
        });
        if (payment && payment.parcelId) {
          await charityCollection.updateOne(
            { _id: new ObjectId(payment.parcelId) },
            { $set: { status } }
          );
        }

        if (paymentUpdate.matchedCount === 0) {
          return res.status(404).send({ message: "Transaction not found" });
        }

        res.send({ success: true, message: "Status updated successfully" });
      } catch (error) {
        console.error("Error updating transaction status:", error);
        res.status(500).send({ message: "Failed to update status" });
      }
    });

    // GET donation details by ID
    app.get("/donations/:id", async (req, res) => {
      try {
        const donation = await donationCollection.findOne({
          _id: req.objectId,
        });
        if (!donation)
          return res.status(404).send({ message: "Donation not found" });
        res.send(donation);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });
    // PATCH confirm pickup (only update status if current status is "Accepted")
    app.patch(
      "/donations/confirm-pickup/:id",
      verifyFirebaseToken,
      verifyCharity,
      async (req, res) => {
        try {
          const result = await donationCollection.updateOne(
            { _id: req.objectId, status: "Accepted" },
            { $set: { status: "Picked Up" } }
          );
          if (result.modifiedCount === 0) {
            return res.status(400).send({ message: "Cannot confirm pickup" });
          }
          res.send({ message: "Marked as Picked Up" });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: "Server error" });
        }
      }
    );
    //GET reviews for a donation by donation ID
    app.get("/reviews/:donationId", async (req, res) => {
      try {
        const donationId = req.params.donationId;
        const reviews = await reviewsCollection
          .find({ donationId: new ObjectId(donationId) })
          .sort({ createdAt: -1 })
          .toArray();
        res.send(reviews);
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });
    app.get("/reviews", async (req, res) => {
      try {
        const reviews = await reviewsCollection.find().toArray();
        res.status(200).json(reviews);
      } catch (error) {
        console.error("Failed to get reviews:", error);
        res.status(500).json({ message: "Server error" });
      }
    });

    // POST add a review
    app.post(
      "/reviews",

      async (req, res) => {
        try {
          const { donationId, reviewerName, description, rating, userEmail } =
            req.body;

          if (
            !donationId ||
            !reviewerName ||
            !description ||
            !rating ||
            !userEmail
          ) {
            return res.status(400).send({ message: "Missing required fields" });
          }

          const review = {
            donationId: new ObjectId(donationId),
            reviewerName,
            description,
            rating: Number(rating),
            userEmail, // Store who wrote the review
            createdAt: new Date(),
          };

          const result = await reviewsCollection.insertOne(review);
          res.status(201).send({
            message: "Review added",
            reviewId: result.insertedId,
            review: review, // Send back the full review object
          });
        } catch (error) {
          console.error(error);
          res.status(500).send({ message: "Server error" });
        }
      }
    );
    //--------POST save to favorites---------------
    app.post("/favorites", async (req, res) => {
      try {
        const { donationId, userEmail } = req.body;
        if (!donationId || !userEmail) {
          return res
            .status(400)
            .send({ message: "Missing donationId or userEmail" });
        }
        // Check if already in favorites
        const exists = await favoritesCollection.findOne({
          donationId,
          userEmail,
        });
        if (exists) {
          return res.status(400).send({ message: "Already in favorites" });
        }
        const result = await favoritesCollection.insertOne({
          donationId,
          userEmail,
          addedAt: new Date(),
        });
        res.status(201).send({
          message: "Added to favorites",
          favoriteId: result.insertedId,
        });
      } catch (error) {
        console.error(error);
        res.status(500).send({ message: "Server error" });
      }
    });
    //-----------dona-request
    app.post("/donation-requests", async (req, res) => {
      try {
        const request = req.body;
        const result = await donationRequestsCollection.insertOne(request);
        res.send(result);
      } catch (error) {
        console.error("Error saving donation request:", error);
        res.status(500).send({ error: "Failed to save request" });
      }
    });

    // Charity Requests Endpoint
    app.get(
      "/donation-requests",
      verifyFirebaseToken,
      verifyCharity,

      async (req, res) => {
        try {
          const charityEmail = req.user.email;

          const requests = await donationRequestsCollection
            .find({ charityEmail })
            .toArray();

          res.json(requests);
        } catch (error) {
          console.error("Error fetching donation requests:", error);
          res.status(500).json({ message: "Internal server error" });
        }
      }
    );

    // Cancel Request Endpoint
    app.delete(
      "/donation-requests/:id",
      verifyFirebaseToken,
      verifyCharity,
      async (req, res) => {
        try {
          const { id } = req.params;
          const result = await donationRequestsCollection.deleteOne({
            _id: new ObjectId(id),
            status: "Pending", // Only allow cancel if status is Pending
          });

          if (result.deletedCount === 0) {
            return res
              .status(400)
              .json({ message: "Request not found or cannot be cancelled" });
          }

          res.json({ success: true });
        } catch (error) {
          res.status(500).json({ message: "Failed to cancel request" });
        }
      }
    );
    ////requ-donation
    app.get("/api/donation-requests", async (req, res) => {
      try {
        const requests = await donationRequestsCollection.find({}).toArray();
        res.json(requests);
      } catch {
        res.status(500).json({ message: "Internal server error" });
      }
    });
   app.get("/api/donation-requests/:id", async (req, res) => {
  const { id } = req.params;

  if (!ObjectId.isValid(id)) {
    return res.status(400).json({ message: "Invalid request ID" });
  }

  try {
    const request = await donationRequestsCollection.findOne({
      _id: new ObjectId(id),
    });

    if (!request) {
      return res.status(404).json({ message: "Donation request not found" });
    }

    res.json(request);
  } catch (error) {
    res.status(500).json({ message: "Internal server error" });
  }
});

    app.patch("/api/donation-requests/:id",verifyRestaurant, async (req, res) => {
      const requestId = req.params.id;
      const { action, donationId } = req.body;

      if (!["Accepted", "Rejected"].includes(action)) {
        return res.status(400).json({ message: "Invalid action" });
      }

      try {
        await donationRequestsCollection.updateOne(
          { _id: new ObjectId(requestId) },
          { $set: { status: action } }
        );

        if (action === "Accepted") {
          await donationRequestsCollection.updateMany(
            { donationId, _id: { $ne: new ObjectId(requestId) } },
            { $set: { status: "Rejected" } }
          );
        }

        res.json({ message: `Request ${action.toLowerCase()} successfully` });
      } catch {
        res.status(500).json({ message: "Internal server error" });
      }
    });
    //mypickup
    app.patch("/pickup/donation-requests/:id",verifyFirebaseToken,verifyCharity, async (req, res) => {
      const id = req.params.id;
      const { status } = req.body;

      const result = await donationRequestsCollection.updateOne(
        { _id: new ObjectId(id) },
        { $set: { status } }
      );

      res.send(result);
    });
    // Get all donation requests for a specific charity
    app.get(
      "/donation-requests/charity/:email",
      verifyFirebaseToken,
      async (req, res) => {
        const email = req.params.email;

        try {
          const requests = await donationRequestsCollection
            .find({ charityEmail: email })
            .toArray();

          res.send(requests);
        } catch (err) {
          res.status(500).send({ error: "Failed to fetch donation requests" });
        }
      }
    );
    //----------------favorate-----------
    app.get("/favorites", verifyFirebaseToken, async (req, res) => {
      try {
        const { userEmail } = req.query;

        if (!userEmail) {
          return res.status(400).json({ message: "userEmail is required" });
        }

        const favorites = await favoritesCollection
          .find({ userEmail })
          .toArray();

        res.json(favorites);
      } catch (error) {
        res.status(500).json({ message: "Failed to fetch favorites", error });
      }
    });
    app.delete("/favorites/:id", verifyFirebaseToken, async (req, res) => {
      try {
        const favoriteId = req.params.id;

        const result = await favoritesCollection.deleteOne({
          _id: new ObjectId(favoriteId),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Favorite not found" });
        }

        res.json({ message: "Removed from favorites" });
      } catch (error) {
        res.status(500).json({ message: "Failed to remove favorite", error });
      }
    });

    // GET /api/reviews?userEmail=email@example.com
    app.get("/api/reviews", async (req, res) => {
      const { userEmail } = req.query;
      if (!userEmail) {
        return res
          .status(400)
          .json({ error: "Missing userEmail query parameter" });
      }

      try {
        const reviews = await reviewsCollection
          .aggregate([
            { $match: { userEmail } },
            {
              $addFields: { donationObjectId: { $toObjectId: "$donationId" } },
            },
            {
              $lookup: {
                from: "donations",
                localField: "donationObjectId",
                foreignField: "_id",
                as: "donationInfo",
              },
            },
            { $unwind: "$donationInfo" },
            { $sort: { createdAt: -1 } },
          ])
          .toArray();

        res.json(reviews);
      } catch (error) {
        console.error("Error fetching reviews:", error);
        res.status(500).json({ error: "Server error fetching reviews" });
      }
    });
    // DELETE /api/reviews/:reviewId
    app.delete("/api/reviews/:reviewId", async (req, res) => {
      const { reviewId } = req.params;

      if (!ObjectId.isValid(reviewId)) {
        return res.status(400).json({ error: "Invalid review ID" });
      }

      try {
        // Use deleteOne instead - more reliable
        const { deletedCount } = await reviewsCollection.deleteOne({
          _id: new ObjectId(reviewId),
        });

        console.log("Deleted count:", deletedCount);

        if (deletedCount === 0) {
          return res.status(404).json({ error: "Review not found" });
        }

        // Return the deleted ID for verification
        res.json({
          message: "Review deleted successfully",
          deletedId: reviewId,
        });
      } catch (error) {
        console.error("Full error:", error);
        res.status(500).json({
          error: "Server error deleting review",
          details: error.message,
        });
      }
    });
    ///------admin-managerequest---
    app.get("/api/charity-requests",verifyFirebaseToken,verifyAdmin, async (req, res) => {
      try {
        const requests = await donationRequestsCollection.find({}).toArray();
        res.json(requests);
      } catch (error) {
        console.error("Error fetching charity requests:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Delete a charity request by ID
    app.delete("/api/charity-requests/:id", async (req, res) => {
      const id = req.params.id;

      if (!ObjectId.isValid(id)) {
        return res.status(400).json({ message: "Invalid request ID" });
      }

      try {
        const result = await donationRequestsCollection.deleteOne({
          _id: new ObjectId(id),
        });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: "Request not found" });
        }

        res.json({ message: "Request deleted successfully" });
      } catch (error) {
        console.error("Error deleting charity request:", error);
        res.status(500).json({ message: "Internal server error" });
      }
    });
    /////--------------statistics----------------------
    app.get("/restaurant/statistics/:email", async (req, res) => {
      try {
        const email = req.params.email;
        const donations = await donationCollection
          .find({ restaurantEmail: email })
          .toArray();

        const statistics = {};

        donations.forEach((donation) => {
          const type = donation.foodType?.trim();
          const quantityString = donation.quantity;

          const match = quantityString.match(/(\d+(?:\.\d+)?)/);
          const quantity = match ? parseFloat(match[1]) : 0;

          if (!statistics[type]) {
            statistics[type] = 0;
          }
          statistics[type] += quantity;
        });

        const formattedStats = Object.entries(statistics).map(
          ([type, total]) => ({
            foodType: type,
            totalQuantity: total,
          })
        );

        res.send(formattedStats);
      } catch (error) {
        console.error("Error generating donation statistics:", error);
        res.status(500).send({ message: "Failed to generate statistics" });
      }
    });
    // Assuming you have express app and MongoDB connection setup
    app.get("/api/charity-requests/latest", async (req, res) => {
      try {
        const requests = await charityCollection
          .find({})
          .sort({ createdAt: -1 }) // Sort by newest first
          .limit(3)
          .toArray();

        res.json(requests);
      } catch (err) {
        console.error("Error fetching latest charity requests:", err);
        res.status(500).json({ message: "Internal server error" });
      }
    });

    // Example: GET /api/dashboard-overview?email=someone@gmail.com
    app.get("/api/dashboard-overview", async (req, res) => {
      const email = req.query.email;
      const user = await usersCollection.findOne({ email });

      if (!user) return res.status(404).json({ message: "User not found" });

      let stats = { role: user.role };

      if (user.role === "Admin") {
        stats.totalDonations = await donationsCollection.countDocuments();
        stats.totalPickups = await donationRequestsCollection.countDocuments({
          status: "Picked Up",
        });
        stats.activeUsers = await usersCollection.countDocuments();
      } else if (user.role === "Restaurant") {
        stats.organizationName = user.organization;
        stats.totalDonations = await donationsCollection.countDocuments({
          restaurantEmail: email,
        });
        stats.totalPickups = await donationRequestsCollection.countDocuments({
          restaurantEmail: email,
          status: "Picked Up",
        });
      } else if (user.role === "Charity") {
        stats.organizationName = user.organization;
        stats.totalPickups = await donationRequestsCollection.countDocuments({
          charityEmail: email,
          status: "Picked Up",
        });
        stats.pendingRequests = await donationRequestsCollection.countDocuments(
          { charityEmail: email, status: "Pending" }
        );
      } else {
        stats.favorites = await favoritesCollection.countDocuments({
          userEmail: email,
        });
        stats.reviews = await reviewsCollection.countDocuments({
          userEmail: email,
        });
      }

      res.json(stats);
    });

    // Send a ping to confirm a successful connection
    //await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    //await client.close();
  }
}
run().catch(console.dir);

// Example Route
app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

// Start Server
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});
