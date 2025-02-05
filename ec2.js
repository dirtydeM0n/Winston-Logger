const express = require("express");
const http = require("http");
const { Decrypt } = require("./decrypt");
const app = express();
const server = http.createServer(app);

app.use("/logs", express.json());

app.post("/logs", (req, res) => {
  const { timestamp, level, message } = req.body;
  console.log(`${timestamp} - ${Decrypt(message)}`);
  return res.status(200).send("Log received");
});

const PORT = 3001;
server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
