async function authValidate(r) {
  const basicAuth = r.headersIn['Authorization'];
  if (!basicAuth.toLowerCase().startsWith("basic")) {
    r.error("Only BasicAuth is supported");
    r.return(401);
    return;
  }
  const basicAuthDecoded = atob(basicAuth.replace(/Basic/gi, "").trim());
  const keys = basicAuthDecoded.split(":");
  const query = `
  query GetJWTForClientCredentials($accessKey: String!, $secretKey: String!) {
    getJWTForClientCredentials (data:{
        accessKey: $accessKey,
        secretKey: $secretKey
    })
}`;
  if (keys.length < 2) {
    r.error("Username or password is missing");
    r.return(401);
    return;
  }
  const authBody = {
    operationName: "GetJWTForClientCredentials",
    query:         query,
    variables: {
      accessKey: keys[0],
      secretKey: keys[1]
    }
  };
  const resp = await ngx.fetch('https://console.cloud.timescale.com/api/query',
    {
      method: "POST",
      body: JSON.stringify(authBody),
      headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json'
      },
    });
  if (!resp.ok) {
    r.error(resp.ok + "," + resp.status);
    r.return(resp.status);
    return;
  }
  const jsonResp = await resp.json();
  if (jsonResp["errors"] != null) {
    r.error(JSON.stringify(jsonResp));
    r.return(401);
    return;
  }
  const claims = jwtClaim(jsonResp.data.getJWTForClientCredentials);
  for (const claim in claims) {
    r.headersOut["x-" + claim.toLowerCase()] = claims[claim];
  }
  r.error(JSON.stringify(r.headersOut));
  r.return(200);
}

function jwtClaim(jwtToken) {
  const segments = jwtToken.split(".");
  const payload = String.bytesFrom(segments[1], 'base64');
  return JSON.parse(payload)
}

export default {authValidate};
