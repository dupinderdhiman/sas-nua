const express = require('express');
const axios = require('axios');

const app = express();

// Define the route that accepts tenantAuthReqId as a query parameter
app.get('/auth', async (req, res) => {
  const { tenantAuthReqId } = req.query;

  if (!tenantAuthReqId) {
    return res.status(400).send('tenantAuthReqId is required');
  }

  try {
    // Generate the callback URL dynamically, including tenantAuthReqId and Authorization as query parameters
    const redirectUrl = `http://localhost:8080/tenant-authentication-callback?tenantAuthReqId=${tenantAuthReqId}&Authorization=Bearer%20hrg`;
  
    // Redirect the user back to the tenant-authentication-callback URL
    res.redirect(redirectUrl);
  } catch (error) {
    console.error('Error in redirect:', error);
    res.status(500).send('Redirect failed');
  }
});

// Start the server
const PORT = 4200;
app.listen(PORT, () => {
  console.log(`Node.js service running on http://localhost:${PORT}`);
});