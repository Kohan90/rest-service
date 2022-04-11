const express = require("express")
const mongo = require("mongodb").MongoClient
const dbo = require('./db/conn')

const PORT = process.env.PORT || 3001

const app = express()

app.use(require('./routes/token'))

// perform a database connection when the server starts
dbo.connectToServer(function (err) {
    if (err) {
      console.error(err);
      process.exit();
    }
  
    // start the Express server
    app.listen(PORT, () => {
      console.log(`Server is running on port: ${PORT}`);
    });
  });