const express = require("express");
const cors = require("cors");

const { MongoClient, ServerApiVersion } = require("mongodb");

require("dotenv").config();

const app = express();
const port = process.env.PORT || 7000;

// Middleware
app.use(cors());
app.use(express.json());

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
    await client.connect();
    const donationCollection = client.db("donationdb").collection("donations");
    const usersCollection = client.db("donationdb").collection("loggedUser");
    //register
    app.post("/users", async (req, res) => {
      const user = req.body;
      const existing = await usersCollection.findOne({ email: user.email });
      if (existing) {
        return res.status(400).json({ message: "User already exists" });
      }
      const result = await usersCollection.insertOne(user);
      res.send(result);
    });

    //Add donation
    app.post("/api/donations", async (req, res) => {
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
    });
    //All Donation
    app.get("/all/donations", async (req, res) => {
      const result = await donationCollection.find().toArray();
      res.send(result);
    });
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
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
