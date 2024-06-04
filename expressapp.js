const express = require("express");
const path = require("path");
const app = express();
const PORT = process.env.PORT || 3000
const fs = require("fs")
const crypto = require("crypto")


app.set("views", path.join(__dirname, "views"))
app.set("view engine", "pug")



const tls = require('tls')
const TIMEOUT = 3000


const getRemainingDays = date => {
  const expiry = new Date(date).valueOf()
  const now = new Date().valueOf()
  return ((expiry - now) / 1000 / 60 / 60 / 24).toFixed(2)
}

const getCertExpiry = (host, port, servername) => {
  return new Promise((resolve, reject) => {
    const result = {}
    const socket = tls.connect({ host, port, servername, rejectUnauthorized: false })
    socket.setTimeout(TIMEOUT)
    socket.once('secureConnect', () => {
      const peerCert = socket.getPeerCertificate(true)
      result.remoteip = socket.remoteAddress
      result.validFrom = peerCert.valid_from
      result.validTo = peerCert.valid_to
      result.peerCert = peerCert
      socket.destroy()
    })
    socket.once('close', () => resolve(result))
    socket.once('error', reject)
    socket.once('timeout', () => {
      socket.destroy(new Error(`Timeout after ${TIMEOUT} ms for ${servername}:${port}`))
    })
  })
}

const checkCertExpiration = async (host, port = 443, servername = host) => {
  const { remoteip, validTo, peerCert } = await getCertExpiry(host, port, servername)
  const remainingDays = getRemainingDays(validTo)
  return { remoteip, validTo, remainingDays, peerCert }
}




app.use(express.urlencoded({
  extended: true
}))
app.get('/', (req, res) => {
  res.render("index", { title: "SSL Checker" })
})
app.get('/decoder', (req, res) => {
  res.render("index", { title: "SSL Checker" })
})
app.get('/sslresults', (req, res) => {
  res.render("index", { title: "SSL Checker" })
})

app.post("/decoder", (req, res) => {
  try {
    let pemcert = req.body.cert
    if (!pemcert.startsWith("-----")){
      let buff = Buffer.from(pemcert, 'base64');
      var prefix = '-----BEGIN CERTIFICATE-----\n';
      var postfix = '-----END CERTIFICATE-----';
      var pemText = prefix + buff.toString('base64').match(/.{0,64}/g).join('\n') + postfix;
      pemcert = pemText
    }
    const cert = new crypto.X509Certificate((pemcert))
    let subjects = (cert.subject)
    //console.log(subjects.replaceAll('\n', ',')) 
    newobj = subjects.replaceAll('\n', ', ')
    const remainingDays = getRemainingDays(cert.validTo)
    if (cert.subjectAltName){
      SANs = cert.subjectAltName.replaceAll('DNS:', '')
    }else {
      SANs = cert.subjectAltName
    }
    let decodedinfo = {
      "subject": newobj,
      "san": SANs,
      "issuer": cert.issuer,
      "validfrom": cert.validFrom,
      "validuntill": cert.validTo,
      "daysleft": remainingDays,
      "fingerprint": cert.fingerprint,
      "serialNumber": cert.serialNumber
    }
    res.render("decoderesult", { title: "Certificate Decoder Results", resultes: decodedinfo })

  } catch (err) {
    errorobj = { "error": err }
    res.render("decodeerror", { title: "Certificate Decoder Results", resultes: errorobj })
  }
}
)

function extractHostname(url) { /// this is to format the url
  var hostname;
  //find & remove protocol (http, ftp, etc.) and get hostname

  if (url.indexOf("//") > -1) {
    hostname = url.split('/')[2];
  } else {
    hostname = url.split('/')[0];
  }

  //find & remove port number
  hostname = hostname.split(':')[0];
  //find & remove "?"
  hostname = hostname.split('?')[0];
  //console.log(hostname)
  return hostname;
}


app.post("/sslresults", (req, res) => {
  const notformattedurl = req.body.url
  formattedurl = extractHostname(notformattedurl)
  console.log("SSL Check Requested for domain: ", formattedurl)
  const main = async (hosts) => {
    const domains = hosts
    const tasks = domains.map(domain => checkCertExpiration(domain))
    const results = await Promise.allSettled(tasks)

    for (let i = 0; i < domains.length; i++) {
      const result = results[i]
      if (result.status === 'fulfilled') {
        const { remoteip, validTo, remainingDays, peerCert } = result.value
        var obj = [];
        // console.dir(peerCert["subjectaltname"].replaceAll('DNS:',''))
        let domaininfo = {
          "domain": domains[i], "san": peerCert["subjectaltname"].replaceAll('DNS:', ''), "daysleft": remainingDays, "CN": peerCert["subject"]["CN"], "validuntill": validTo, "Organization": peerCert["subject"]["O"], "issuer": peerCert["issuer"]["CN"],
          "validfrom": peerCert["valid_from"], "fingerprint": peerCert["fingerprint"], "serialNumber": peerCert["serialNumber"]
        }


        let intermediatecert = peerCert["issuerCertificate"]
        let inermedcertdata = {
          "CN": intermediatecert["subject"]["CN"], "validuntill": intermediatecert["valid_to"], "Organization": intermediatecert["subject"]["O"], "issuer": intermediatecert["issuer"]["CN"],
          "validfrom": intermediatecert["valid_from"], "fingerprint": intermediatecert["fingerprint"], "serialNumber": intermediatecert["serialNumber"]
        };
        obj.push(inermedcertdata);

        //console.dir(peerCert["issuerCertificate"]);
        let rootcertificate = intermediatecert["issuerCertificate"]
        let rootcertdata = {
          "CN": rootcertificate["subject"]["CN"], "validuntill": rootcertificate["valid_to"], "Organization": rootcertificate["subject"]["O"], "issuer": rootcertificate["issuer"]["CN"],
          "validfrom": rootcertificate["valid_from"], "fingerprint": rootcertificate["fingerprint"], "serialNumber": rootcertificate["serialNumber"]
        };
        obj.push(rootcertdata);
        //res.json(`Username is : ${leafcert}`)
        //var resultsssl = {
        //  leafcert,inermedcertdata,rootcertdata
        //}
        // 
        let obj1 = {
          remoteip,
          domaininfo,
          obj
        }
        //console.log(obj1)
        //res.setHeader('Content-Type', 'application/json');
        res.render("resultpug", { title: "SSL Checker results", resultes: obj1 })
      } else {
        console.error(`Error checking ${domains[i]}: ${result.reason}`)
        errorobj = { "error": result.reason }
        res.render("errorresultpug", { title: "SSL Checker results", resultes: errorobj })
      }
    }
  }
  main([formattedurl])

})
app.listen(PORT, () => {
  console.log(`Listening on ${PORT}`)
})
