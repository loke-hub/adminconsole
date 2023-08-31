/***
 @ModifiedBy Bhuvaneshwari Balasubramaniyam
 @email bhuvaneshwari.b@sensiple.com
 @created date 2022-12-18 19:40:00
 @ModifiedDate 2023-02-17 17:05:12
 @desc API file for QA
***/

'use strict'

const express = require('express');
const app = express();
const helmet = require("helmet");
var MySql = require('sync-mysql');
const expressSanitizer = require('express-sanitizer');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const cors = require('cors');
var CryptoJS = require("crypto-js");
var Joi = require('joi');
var moment = require('moment');
const nodemailer = require('nodemailer');
const CSMongo = require('./mongo-database-middleware/conversense_mongo_connect');
const CSSql = require('./sql-database-middleware/conversense_sql_connect');
var checkLength = {}
const axios = require('axios');
require('dotenv').config();
const CREDENTIALS = JSON.parse(process.env.CREDENTIALS);
var mongoDBurl = CREDENTIALS["dburl"];
var database = CREDENTIALS["mongodatabase"];
const wsApiSecrectkey = 'WSUthT0k8Q8q,MV36DfQ*Y#';


app.use(helmet());
app.use(helmet.contentSecurityPolicy());
app.use(helmet.dnsPrefetchControl());
app.use(helmet.expectCt());
app.use(
  helmet.frameguard({
    action: "deny",
  })
);
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts());
app.use(helmet.ieNoOpen());
app.use(helmet.noSniff());
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.referrerPolicy());
app.use(helmet.xssFilter());

app.use(expressSanitizer());

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.raw());


function checkIfStringHasSpecialChar(_string) {
  // changes by Joeal
  let spChar = "/[!@#$%^&*()+\-\[\]{};':\\|.<>\/?]+/";
  for (var i = 0; i < _string.length; i++) {
    if (spChar.indexOf(_string.charAt(i)) != -1) {
      return true;
    }
  }
  return false;
}

var CustomMiddleware = function (req, res, next) {
  res.setHeader("Content-Security-Policy", "script-src 'self';");
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");

  var _urlString = req.path.replace(/\//g, "");
  if (_urlString.length > 0 && req.method === 'GET') {
    var _true = checkIfStringHasSpecialChar(_urlString);

    if (_true) {
      return res.status(400).json({ errors: "Bad Request!" })
    }
  }

  if (_urlString.length > 0 && req.method === 'POST') {
    const _reqBodydata = req.body;
    var _sanitizer = false;
    Object.keys(_reqBodydata).forEach(function (key) {
      if (_reqBodydata[key].length > 0) {
        _sanitizer = checkIfStringHasSpecialChar(_reqBodydata[key]);
        if (_sanitizer) {
          return res.sendStatus(400).json({ errors: "Bad Request!" })
        }
      }
    })
  }
  next()
}

app.use(CustomMiddleware)
app.use(express.static('public'))
app.use(cors());
app.options('*', cors());
app.use(function (req, res, next) {
  // Website you wish to allow to connect
  res.setHeader('Access-Control-Allow-Origin', '*');
  // Request methods you wish to allow
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, PATCH, DELETE');
  // Request headers you wish to allow
  res.setHeader('Access-Control-Allow-Headers', 'X-Requested-With,content-type');
  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader('Access-Control-Allow-Credentials', true);
  // Pass to next layer of middleware
  next();
});


function encryptedJson(plainText) {

  var b64 = CryptoJS.AES.encrypt(plainText, wsApiSecrectkey).toString();
  var e64 = CryptoJS.enc.Base64.parse(b64);
  var eHex = e64.toString(CryptoJS.enc.Hex);
  return eHex;
}

function decodedJson(cipherText) {
  var reb64 = CryptoJS.enc.Hex.parse(cipherText);
  var bytes = reb64.toString(CryptoJS.enc.Base64);
  var decrypt = CryptoJS.AES.decrypt(bytes, wsApiSecrectkey);
  var plain = decrypt.toString(CryptoJS.enc.Utf8);
  return plain;
}

function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const bearer = bearerHeader.split(" ");
    const brearerToken = bearer[1];
    req.token = brearerToken;
    jwt.verify(req.token, wsApiSecrectkey, (err, token) => {
      if (!token) {
        res.json({ message: "Invalid Key" });
      }
      req.token = token;
      next()
    })
  } else {
    res.json({ message: "Please Enter your Access Key" });
  }
}

var connection;
function _checkDB(databasetype) {
  if (databasetype.toLowerCase() === 'mysql') {
    connection = new MySql({
      host: CREDENTIALS['host'],
      user: CREDENTIALS['user'],
      password: decodedJson(CREDENTIALS['password']),
      database: CREDENTIALS['sqldatabase'],
      port: CREDENTIALS['port']

    });
    var DataBase = new CSSql();
    return DataBase;
  } else if (databasetype.toLowerCase() === 'mongodb') {
    var DataBase = new CSMongo();
    connection = DataBase.db_connectivity(mongoDBurl, database);
    return DataBase;
  } else {
    console.log("Enter Valid Input");
  }
}

const DataBase = _checkDB(CREDENTIALS["DatabaseType"]);

//SigIn - Except agent can sigin admin console page
app.post("/signin", async (req, res) => {

  var login_time = decodedJson(req.body.login_time);
  var username = decodedJson(req.body.username);
  var password = decodedJson(req.body.password);

  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com'] } }),
    password: (Joi.string().max(15).min(8).required())
  })
  var validate = schema.validate({ email: username, password: password });
  if (validate.error) {
    res.status(500).json({ message: "please provide valid credentials" });
  }
  var user_list = await DataBase.db_select(connection, "cs_users", { email: username });
  if (user_list.length) {
    let user_role = user_list[0].role_id;
    let temp_password = user_list[0].is_temp_password;
    if (user_role === 4) {
      res.status(500).json({ message: "you dont have an access right now" })
    } else {
      if (temp_password === 1) {
        res.status(200).json({ message: "please reset your password right now" })
      }
      else {
        let DB_Password = decodedJson(user_list[0].password)
        let user_id = user_list[0].id
        if (DB_Password === password) {
          await DataBase.db_update(connection, "cs_users", { agent_status: 1, end_time: login_time, type: 'CUSTOM', status_intext: 'Available', login_time: login_time }, { id: user_id })
          const accessToken = jwt.sign({ 'userid': user_id, 'email': username }, wsApiSecrectkey, {
            expiresIn: "18h"
          })
          const refreshToken = jwt.sign({ 'userid': user_id, 'email': username }, wsApiSecrectkey, {
            expiresIn: "30d"
          })
          return res.status(200).json({ accessToken, refreshToken });
        }
        else if (DB_Password !== req.body.password) {
          res.status(403).json({ message: " please provide valid mail id and password" })
        }
      }
    }
  } else {
    res.status(500).json({ message: "please provide valid credentials" });
  }

})


// forget password
app.post("/forgetpassword", async (req, res) => {
  var Email = req.body.Email;
  var username = decodedJson(Email);
  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com'] } })
  })
  var validate = schema.validate({ email: username });
  if (validate.error) {
    res.status(500).json({ message: "please provide valid Email" })
  }
  else {
    var UserEmailList = await DataBase.db_select(connection, "cs_users", { email: username });
    if (!UserEmailList.length) {
      return res.status(500).json({ message: "you dont have an account" })
    }
    else {
      let mailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
          user: 'lokeshwarisbeece@gmail.com',
          pass: 'ffti hxjj ppjo livz'
        }
      });
      var VerificationCode = Math.floor(1000 + Math.random() * 9000);
      let mailDetails = {
        from: 'dialogueflow26@gmail.com',
        to: username,
        subject: 'forget password verification code ',
        text: "Your forget password verification code is " + VerificationCode + ""
      };
      mailTransporter.sendMail(mailDetails, async function (err, InsertUserCode) {
        if (err) {
          res.status(500).send(err);
        } else {
          console.info("forget password verification code is", VerificationCode);
          console.info("Email sent successfully");
          await DataBase.db_update(connection, "cs_users", { verification_code: parseInt(VerificationCode) }, { email: username })
          res.status(200).json({ message: "verificatin code for forget password is send successfully to your mail id" })
        }
      });
    }
  }
})

//reset password
app.post("/resetpassword", async (req, res) => {
  var VerifyCode = (req.body.VerifyCode)
  var Email = (req.body.Email)
  var username = decodedJson(Email)
  var password = (req.body.password);
  var confirmpassword = (req.body.confirmpassword);
  var DecodedPassword = decodedJson(password);
  var DecodeConfirmPassword = decodedJson(confirmpassword)
  const schema = Joi.object({
    Password: Joi.string().min(8).alphanum().required()
  })
  var validate = schema.validate({ Password: password });
  if (validate.error) {
    res.status(500).json({ message: "please provide valid password" });
  }
  if (DecodedPassword !== DecodeConfirmPassword) {
    res.status(500).json({ message: "your password and confirmpassword should match" })
  }
  else {
    var QueryVerificationCode = await DataBase.db_select(connection, "cs_users", { email: username });
    var verifiycode = QueryVerificationCode[0].verification_code;
    if ((parseInt(verifiycode) !== parseInt(VerifyCode))) {
      res.status(500).json({ message: "invalid verification code" });
    }
    else {
      await DataBase.db_update(connection, "cs_users", { password: password }, { verification_code: parseInt(VerifyCode) });
      res.status(200).json({ message: "password updated successfully" });
    }
  }
})

app.post("/updatepassword", async (req, res) => {
  var Email = (req.body.Email)
  var DecodeEMail = decodedJson(Email)
  var Password = (req.body.password);
  var confirmpassword = (req.body.confirmpassword);
  var DecodedPassword = decodedJson(Password);
  var DecodeConfirmPassword = decodedJson(confirmpassword)
  const schema = Joi.object({
    Password: Joi.string().min(8).alphanum().required()
  })
  var validate = schema.validate({ Password: Password });
  if (validate.error) {
    res.status(500).json({ message: "please provide valid password" })
  }
  if (DecodedPassword !== DecodeConfirmPassword) {
    res.status(500).json({ message: "your password and confirmpassword should match" })
  }
  else {
    await DataBase.db_update(connection, "cs_users", { password: Password, is_temp_password: 0 }, { email: DecodeEMail })
    res.status(200).json({ message: "password updated successfully" });
  }
})

app.post('/sso', async (req, res) => {
  var obj = req.body;
  obj.email = decodedJson(obj.email);
  obj.login_time = decodedJson(obj.login_time);
  obj.client_id = 1;
  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com'] } }).required()
  });
  var validate = schema.validate({ email: obj.email });
  if (validate.error) {
    res.status(500).json({ message: "please provide valid credentials" });
  }
  var user_object_list = await DataBase.db_select(connection, "cs_users", { email: obj.email });
  if (!user_object_list.length) {
    obj.first_name = decodedJson(obj.first_name);
    obj.last_name = decodedJson(obj.last_name);
    obj.name = decodedJson(obj.name);
    obj.date = moment().format("YYYY-MM-DD HH:mm:ss");
    obj.role_id = 2;
    obj.agent_status = 1;
    obj.client_id = 1;
    var user_insert_list = await DataBase.db_insert(connection, "cs_users", [obj])
    var user_id = user_insert_list.insertId;

    await createUseThemeSettings(user_id, obj.client_id);
    await AssignUserPremission(obj.role_id, user_id);

    const accessToken = jwt.sign({ 'userid': user_id, 'email': obj.email }, wsApiSecrectkey, {
      expiresIn: "18h"
    })
    const refreshToken = jwt.sign({ 'userid': user_id, 'email': obj.email }, wsApiSecrectkey, {
      expiresIn: "30d"
    })
    return res.status(200).json({ accessToken, refreshToken });
  } else {
    var user_id = user_object_list[0].id;
    await DataBase.db_update(connection, "cs_users", { agent_status: 1, end_time: obj.login_time }, { id: user_id })

    const accessToken = jwt.sign({ 'userid': user_id, 'email': obj.email }, wsApiSecrectkey, {
      expiresIn: "18h"
    })
    const refreshToken = jwt.sign({ 'userid': user_id, 'email': obj.email }, wsApiSecrectkey, {
      expiresIn: "30d"
    })
    res.status(200).json({ accessToken, refreshToken });
  }
});

// Get CurrentUser Item
app.get('/getuserinfo/:column', verifyToken, async (req, res) => {
  var _column = req.params.column;
  if (_column === 'all') {
    _column = '*';
  }

  var _userId = req.token.userid;
  let resultA = await DataBase.db_select(connection, "cs_users", { id: parseInt(_userId) });
  res.send(resultA[0])
});

//getuserconfig
app.get('/usersettings/getuserconfig/:column', verifyToken, async (req, res) => {
  var _column = req.params.column;
  if (_column === 'all') {
    _column = '*';
  }
  var _userId = req.token.userid;
  var response = await DataBase.db_select(connection, "cs_usersettings", { user_id: parseInt(_userId) });
  if (_column === 'color_scheme') {
    var normalObj = Object.assign({}, response[0]);
    response = normalObj.color_scheme
  }
  if (_column === 'sidebar') {
    var normalObj = Object.assign({}, response[0]);
    response = normalObj.sidebar
  }
  return res.status(200).send(response);

});
//update usersettings
app.post('/usersettings/updatecolumn/:name', verifyToken, async (req, res) => {
  'use strict';
  const obj = (req.body);
  var _userId = req.token.userid;
  switch (req.params.name) {
    case 'usercolorscheme':
      var color_scheme = '{"dark":' + decodedJson(obj.dark) + ',"light":' + decodedJson(obj.light) + '}';
      var response = await DataBase.db_update(connection, "cs_usersettings", { color_scheme: color_scheme }, { user_id: parseInt(_userId) })
      break;
    case 'usersidebar':
      var sidebar = '{"dark":' + decodedJson(obj.dark) + ',"fixed":' + decodedJson(obj.fixed) + ',"light" :' + decodedJson(obj.light) + ',"condensed":' + decodedJson(obj.condensed) + '}';
      var response = await DataBase.db_update(connection, "cs_usersettings", { sidebar: sidebar }, { user_id: parseInt(_userId) });
      break;
    case 'accesspermission':
      obj.menu_access = (decodedJson(obj.menu_access)).toString();
      console.log(obj.menu_access)
      obj.name = decodedJson(obj.name);
      obj.role_id = parseInt(decodedJson(obj.role_id));
      obj.id = parseInt(decodedJson(obj.id))
      var response = await DataBase.db_update(connection, "cs_access_permissions", { name: obj.name, role_id: parseInt(obj.role_id), menu_access: obj.menu_access }, { id: parseInt(obj.id) })
      break;
  }
  if (response.serverStatus > 1 || response.acknowledged === true) {
    return res.send(response);
  } else {
    return res.status(500).json({ message: "failed" })
  }
});
//get current user item
app.get('/accesspermissions/getuserbyemail/:column', verifyToken, async (req, res) => {
  var _column = req.params.column;
  if (_column === 'all') {
    _column = '*';
  }
  var username = req.token.email;
  var resultA = await DataBase.db_select(connection, "cs_users", { email: username });
  res.send(resultA)
});

// Get roles from current user
app.get('/accesspermissions/getaccesspermissions', verifyToken, async (req, res) => {
  var resultA = await DataBase.db_select(connection, "cs_access_permissions", { published: 1 });
  const ModifyResults = [];
  for (var i = 0; i < resultA.length; i++) {
    var roles = await DataBase.db_select(connection, "cs_roles", { published: 1, id: parseInt(resultA[i].role_id) });
    var usercount = await DataBase.db_count(connection, "cs_users", { role_id: parseInt(resultA[i].role_id) });
    console.info("users count : ", usercount)
    resultA[i].role_name = roles[0].title;
    resultA[i].users_count = usercount;

    ModifyResults.push({ ...resultA[i] })

  };
  res.send(ModifyResults)
});

// get roles
app.get('/accesspermissions/getroles', verifyToken, async (req, res) => {
  var resultA = await DataBase.db_select(connection, "cs_roles", { published: 1 });
  res.send(resultA)
});

//get menus
app.get('/accesspermissions/getmenus', verifyToken, async (req, res) => {
  var _userId = req.token.userid;
  let cs_role_permissions = await DataBase.db_select(connection, "cs_role_permissions", { user_id: parseInt(_userId) })

  if (!cs_role_permissions.length) {
    res.status(500).json({ message: "'The User does not have any access permission, kindly add or existing anyone'" })
  }
  var accessMenus = await DataBase.db_select(connection, "cs_access_permissions", { id: cs_role_permissions[0].access_id })
  var ModifyMenus = JSON.parse(accessMenus[0].menu_access);
  const ModifyResults = []
  for (var element = 0; element < ModifyMenus.length; element++) {
    var menus = await DataBase.db_select(connection, "cs_menus", { id: parseInt(ModifyMenus[element].menuid) })
    ModifyMenus[element].title = menus[0].title
    ModifyResults.push({ ...ModifyMenus[element] })
  }
  res.status(200).send(ModifyResults);
});

//delete access permission
app.get('/accesspermissions/delete/:id', verifyToken, async (req, res) => {
  var acptid = req.params.id;
  await DataBase.db_delete(connection, "cs_access_permissions", { id: parseInt(acptid) })
  await DataBase.db_delete(connection, "cs_role_permissions", { access_id: parseInt(acptid) })
  res.status(200).json({ message: "successfully deleted" })

});

//create accesspermission
app.post('/accesspermissions/createaccesspermission', verifyToken, async (req, res) => {
  const obj = (req.body);
  obj.menu_access = decodedJson(obj.menu_access);
  obj.name = decodedJson(obj.name);
  obj.role_id = parseInt(decodedJson(obj.role_id));
  obj.published = parseInt(decodedJson(obj.published));
  obj.date = decodedJson(obj.date);
  var response = await DataBase.db_insert(connection, "cs_access_permissions", [obj]);
  if (response.insertId > 0) {
    res.status(200).send(response);
  } else {
    res.status(500).json({ message: "failed" })
  }
});

// get accessid 
app.get('/accesspermissions/getacpbyid/:id', verifyToken, async (req, res) => {
  var accessid = req.params.id;
  var resultA = await DataBase.db_select(connection, "cs_access_permissions", { published: 1, id: parseInt(accessid) })
  res.status(200).send(resultA)

});

app.get('/:cid/:pid/:apiname/:actionname', verifyToken, async (req, res) => {
  var clientid = req.params.cid;
  var pid = req.params.pid;
  var apiname = req.params.apiname;
  var actionname = req.params.actionname;
  // apiname = report or channel and actionname = voice or chat 
  var DataReturn = 'Nodata Found';
  switch (apiname) {
    case 'reports':
      DataReturn = 'Null';
      if (actionname === 'realtime') {
        DataReturn = await GoogleConnectRealtime();
      } else if (actionname === 'history') {
        DataReturn = await GoogleConnectHistory();
      } else {
        DataReturn = 'No Valid URL';
      }
      break;
    case 'users':
      if (actionname === 'listing') {
        DataReturn = await GoogleListUsers();
      } else {
        DataReturn = 'No Valid URL';
      }
      break;
    case 'channel':
      DataReturn = channel(actionname);
      break;
  }
  console.log("Results " + clientid + pid + apiname + actionname + ', === ', DataReturn);
  res.status(200).send(DataReturn)

});

async function GoogleConnectRealtime() {
  return null;
}
async function GoogleListUsers() {
  return null;
}

// skillgroup  Rest Api 
//GET SkillGroup listing. 
app.get('/skillgroups/getskillgroup', verifyToken, async (req, res) => {
  var skillGroupItem = await DataBase.db_select(connection, "cs_skillgroup", {})
  for (var i = 0; i < skillGroupItem.length; i++) {
    var gAgent = skillGroupItem[i].group_agents;
    var gAgentCount = gAgent.split(',');
    skillGroupItem[i].name = decodedJson(skillGroupItem[i].name);
    skillGroupItem[i].description = decodedJson(skillGroupItem[i].description);
    skillGroupItem[i].assigned_agents = gAgentCount.length
  }
  res.status(200).send(skillGroupItem);
});

// GET Single Skill Group object 
app.get('/skillgroups/skillgroupitem/:id', verifyToken, async (req, res) => {
  var id = req.params.id;
  var sKgObject = await DataBase.db_select(connection, "cs_skillgroup", { id: parseInt(id) });
  var skillgroupItem = [];
  skillgroupItem.push({ id: id, name: decodedJson(sKgObject[0].name), description: decodedJson(sKgObject[0].description), group_agents: sKgObject[0].group_agents, bot_id: sKgObject[0].bot_id, skill_list: sKgObject[0].skill_list, channels: sKgObject[0].channels, published: sKgObject[0].published })

  res.status(200).send(skillgroupItem)
});

// Change Skill group status object 
app.post('/skillgroups/updateskillgroup', verifyToken, async (req, res) => {
  const obj = (req.body);
  // console.log('obj', JSON.stringify(obj));
  obj.published = decodedJson(obj.published);
  var id = decodedJson(obj.id);
  var gSUpdateResponse = await DataBase.db_update(connection, "cs_skillgroup", { published: parseInt(obj.published) }, { id: parseInt(id) });
  if (gSUpdateResponse.serverStatus > 1 || gSUpdateResponse.acknowledged === true) {
    return res.status(200).json({ message: "successfully updated" });
  } else {
    return res.status(500).json({ message: "failed" })
  }

});

// create skillgroup
app.post('/skillgroups/create', verifyToken, async (req, res) => {
  const obj = (req.body);
  obj.group_agents = decodedJson(obj.group_agents);
  obj.skill_list = decodedJson(obj.skill_list);
  obj.bot_id = decodedJson(obj.bot_id);
  obj.published = parseInt(decodedJson(obj.published));
  obj.channels = decodedJson(obj.channels);
  var result = await DataBase.db_insert(connection, "cs_skillgroup", [obj])
  if (result.insertId > 0) {
    return res.status(200).json({ message: "successfully updated" });
  } else {
    return res.status(500).json({ message: "failed" })
  }

});

// update skillgroup by id  
app.post('/skillgroups/update/:id', verifyToken, async (req, res) => {
  const obj = (req.body);
  obj.group_agents = decodedJson(obj.group_agents);
  obj.skill_list = decodedJson(obj.skill_list);
  obj.bot_id = decodedJson(obj.bot_id);
  obj.published = parseInt(decodedJson(obj.published));
  obj.channels = decodedJson(obj.channels);
  var response = await DataBase.db_update(connection, "cs_skillgroup", obj, { id: parseInt(req.params.id) })

  if (response.affectedRows > 0 || response.modifiedCount > 0) {
    return res.status(200).json({ message: "successfully updated" });
  } else {
    return res.status(500).json({ message: "failed" })
  }

});

// get skillgroups name
app.get('/skillgroups/name', verifyToken, async (req, res) => {
  var skillgrouplist = await DataBase.db_select(connection, "cs_skillgroup", {})
  res.status(200).send(skillgrouplist);
})

//delete skillgroup
app.post('/skillgroups/delete', verifyToken, async (req, res) => {
  var obj = (req.body);
  obj.id = decodedJson(obj.id);
  obj.published = decodedJson(obj.published);
  var gSDeleteResponse = await DataBase.db_update(connection, "cs_skillgroup", { published: parseInt(obj.published) }, { id: parseInt(obj.id) });
  if (gSDeleteResponse.acknowledged === true || gSDeleteResponse.serverStatus > 1) {
    res.status(200).json({ message: "Successfully Deleted" })
  } else {
    res.sendStatus(501);
  }

});

// GET users listing
app.get('/users/getusers', verifyToken, async (req, res) => {
  var userObjectList = await DataBase.db_select(connection, "cs_users", {});
  for (var i = 0; i < userObjectList.length; i++) {
    var upList = await DataBase.db_select(connection, "cs_userprofiles", { user_id: userObjectList[i].id })
    var roles = await DataBase.db_select(connection, "cs_roles", { published: 1, id: parseInt(userObjectList[i].role_id) });
    for (let j = 0; j < upList.length; j++) {
      var _key = upList[j].profile_key;
      if (_key !== 'active') {
        userObjectList[i][_key] = upList[j].profile_value
      }
    }
    userObjectList[i].role_name = roles[0].title;
  }
  res.status(200).send(userObjectList)
});

//get users info
app.get('/users/getallusers', verifyToken, async (req, res) => {
  var userObjectList = await DataBase.db_select(connection, "cs_users", {})
  const final_result = [];
  for (var i = 0; i < userObjectList.length; i++) {
    var roles = await DataBase.db_select(connection, "cs_roles", { published: 1, id: parseInt(userObjectList[i].role_id) })
    userObjectList[i].role_name = roles[0].title;
    final_result.push({ id: userObjectList[i].id, first_name: userObjectList[i].first_name, last_name: userObjectList[i].last_name, role_id: userObjectList[i].role_id, role_name: userObjectList[i].role_name })
  }
  res.status(200).send(final_result);
})

function CreateUserProfiles(obj) {
  return new Promise(function (resolve, reject) {
    const userProfiles = Object.keys(obj).reduce((accumulator, key) => {
      // Copy all except belows
      if (key !== "first_name" && key !== "last_name" && key !== "email" && key !== "password") {
        accumulator[key] = obj[key]
        DataBase.db_insert(connection, "cs_userprofiles", [{ user_id: obj.userid, profile_key: key, profile_value: obj[key] }])
      }
      return accumulator
    }, {})
    resolve(userProfiles);
  });
}
function createUseThemeSettings(userId, clientId) {
  var color_scheme = { "dark": false, "light": true };
  var sidebar = { "dark": true, "fixed": true, "light": false, "condensed": false };
  return new Promise(function (resolve, reject) {
    var themeresponse = DataBase.db_insert(connection, "cs_usersettings", [{ user_id: userId, client_id: clientId, color_scheme: JSON.stringify(color_scheme), sidebar: JSON.stringify(sidebar) }])

    resolve(themeresponse);
  });
}
function AssignUserPremission(roleId, userId) {
  return new Promise(async function (resolve, reject) {
    var accessResult = await DataBase.db_select(connection, "cs_access_permissions", { role_id: parseInt(roleId) })
    console.info(accessResult)
    var permissionId = accessResult[0].id;
    setTimeout(() => {
      var Roleresponse = DataBase.db_insert(connection, "cs_role_permissions", [{ user_id: parseInt(userId), access_id: parseInt(permissionId) }]);
      resolve(Roleresponse);
    }, 1000);
  });
}

//send email starts
function newaccountsendemail(role_id, email) {
  var Tomail = email;
  var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'kbarticlessendemail@gmail.com',
      pass: 'ntfx qtyp piaf sugl'
    }
  });
  if (parseInt(role_id) === 4) {
    var html = " ";
    html += '<div class="container" style="margin:0px auto ; width:600px ">';
    html += '<div class="top-container" style="color:red">';
    html += '<img src="https://storage.googleapis.com/conversense-uat-09092022.appspot.com/email_template/header.jpg">';
    html += '</div>';
    html += '<div class="middle-container" style=" background-color: #dedbf9;padding: 20px 0px 20px 20px;width: 580px;font-family: Arial, Helvetica, sans-serif; color: #3d3d3d; line-height: 22px; font-size: 16px;  font-weight: normal; margin-top: -4px;">';
    html += ' <p class="user"style="margin: 0px;"><br><br>Dear User,<br><br>Your ConverSense Login Credentials <br>Username: <strong style="color: #3D3D3D;" name="uname">' + Tomail + '</strong> <br>Password: <strong>Sensiple@123</strong> <br><br>This is your default password. It has to be changed on your first login. <br>Please login to the below link to change it.<br><a href="https://conversenseagent-dot-qa-conversense.uc.r.appspot.com/login?returnUrl=%2F"style="text-decoration:none";><strong style="color: #3D3D3D;">https://conversenseagent-dot-qa-conversense.uc.r.appspot.com/login?returnUrl=%2F</strong></a><br><br><div > Thank you<br>ConverSense - Sensiple</div></p><br>';
    html += '</div>';
    html += '<div class="bottom -container"><img src="https://storage.googleapis.com/conversense-uat-09092022.appspot.com/email_template/footer.jpg"></div>'
    html += '</div>'
  }
  else if (parseInt(role_id) !== 4) {
    var html = " ";
    html += '<div class="container" style="margin:0px auto ; width:600px ">';
    html += '<div class="top-container" style="color:red">';
    html += '<img src="https://storage.googleapis.com/conversense-uat-09092022.appspot.com/email_template/header.jpg">';
    html += '</div>';
    html += '<div class="middle-container" style=" background-color: #dedbf9;padding: 20px 0px 20px 20px;width: 580px;font-family: Arial, Helvetica, sans-serif; color: #3d3d3d; line-height: 22px; font-size: 16px;  font-weight: normal; margin-top: -4px;">';
    html += ' <p class="user"style="margin: 0px;"><br><br>Dear User,<br><br>Your ConverSense Login Credentials <br>Username: <strong style="color: #3D3D3D;" name="uname">' + Tomail + '</strong> <br>Password: <strong>Sensiple@123</strong> <br><br>This is your default password. It has to be changed on your first login. <br>Please login to the below link to change it.<br><a href="https://conversenseadmin-dot-qa-conversense.uc.r.appspot.com/login?returnUrl=%2F"style="text-decoration:none";><strong style="color: #3D3D3D;">https://conversenseadmin-dot-qa-conversense.uc.r.appspot.com/login?returnUrl=%2F</strong></a><br><br><div > Thank you<br>ConverSense - Sensiple</div></p><br>';
    html += '</div>';
    html += '<div class="bottom -container"><img src="https://storage.googleapis.com/conversense-uat-09092022.appspot.com/email_template/footer.jpg"></div>'
    html += '</div>'
  }
  let mailOptions = {
    from: 'kbarticlessendemail@gmail.com',
    to: Tomail,
    subject: 'ConverSense new user account details',
    html: html,
  };
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      return false;
    } else {
      console.log('Email has been sent: ' + info.response);
      return true;
    }
  })
}
//mail end

// Create users listing.
app.post('/users/createusers', verifyToken, async (req, res) => {
  const obj = (req.body)[0];
  obj.email = decodedJson(obj.email).replace(/"/g, '');
  obj.password = 'Sensiple@123';
  obj.first_name = decodedJson(obj.first_name);
  obj.last_name = decodedJson(obj.last_name);
  var dbPassword = encryptedJson(obj.password);
  obj.name = obj.first_name + ' ' + obj.last_name;
  obj.client_id = 1;
  obj.role_id = parseInt(decodedJson(obj.role_id));
  obj.date = decodedJson(obj.date);
  // console.log("date", obj.date)
  obj.region = decodedJson(obj.region);
  obj.channels = decodedJson(obj.channels);
  obj.chat_concurrency = decodedJson(obj.chat_concurrency);
  obj.active = 1;
  obj.language = decodedJson(obj.language);
  obj.bot_id = decodedJson(obj.bot_id);
  obj.role_name = decodedJson(obj.role_name);
  obj.login_using = decodedJson(obj.login_using);
  var object = [{ name: obj.name, email: obj.email, is_temp_password: 1, password: dbPassword, client_id: obj.client_id, role_id: obj.role_id, agent_status: 1, first_name: obj.first_name, last_name: obj.last_name, created_date: obj.date, chat_concurrency: parseInt(obj.chat_concurrency), active: obj.active }]
  var response = await DataBase.db_insert(connection, "cs_users", object);
  if (response.insertId > 0 || response.serverStatus > 1 && response.insertId > 0) {
    obj.userid = response.insertId;
    console.log("obj.userid", obj.userid)
    CreateUserPriority(req.body, obj.userid)
    await CreateUserProfiles(obj);
    await createUseThemeSettings(obj.userid, obj.client_id);
    await AssignUserPremission(obj.role_id, obj.userid);
    newaccountsendemail(obj.role_id, obj.email)
    res.status(200).send(response);
  } else {
    res.status(400);
  }

});


function UpdateRolePremission(roleId, _userId) {
  return new Promise(async function (resolve, reject) {
    var accessResult = await DataBase.db_select(connection, "cs_access_permissions", { role_id: parseInt(roleId) })
    var permissionId = accessResult[0].id;
    setTimeout(() => {
      var Roleresponse = DataBase.db_update(connection, "cs_role_permissions", { access_id: parseInt(permissionId) }, { user_id: parseInt(_userId) })
      resolve(Roleresponse);
    }, 2000);
  });
}

function UpdateUserProfiles(obj, _userId) {
  return new Promise(function (resolve, reject) {
    const userProfiles = Object.keys(obj).reduce(async (accumulator, key) => {
      // Copy all except belows
      if (key !== "first_name" && key !== "last_name" && key !== "email" && key !== "password") {
        var deleteData = await DataBase.db_delete(connection, "cs_userprofiles", { user_id: _userId, profile_key: key })
        console.info('Delete User Profiles - ', deleteData);
        if (deleteData.serverStatus > 1 || deleteData.acknowledged === true) {
          setTimeout(async function () {
            var insertUserResponse = await DataBase.db_insert(connection, "cs_userprofiles", [{ user_id: parseInt(obj.user_id), profile_key: key, profile_value: obj[key] }])
            console.log('Insert User Profiles - ', insertUserResponse);
            if (insertUserResponse.serverStatus > 1 || insertUserResponse.insertedCount > 0) {
              console.info('Success');
            } else {
              reject('Server Error');
            }
          }, 200);
        } else {
          reject('Server Error');
        }
      }
      return accumulator
    }, {})

    resolve(userProfiles)

  });

}

async function CreateUserPriority(obj, user_id) {
  var objlength = obj.length;
  var array = []
  for (var i = 1; i < objlength; i++) {
    var users_priority = decodedJson(obj[i].users_priority);
    console.log(users_priority)
    var skillgroup_id = decodedJson(obj[i].skillgroup_id);
    var createagent_priority = await DataBase.db_insert(connection, "cs_users_priority", [{ user_id: parseInt(user_id), users_priority: parseInt(users_priority), skillgroup_id: parseInt(skillgroup_id) }])
    var skillgroup = await DataBase.db_select(connection, "cs_skillgroup", { id: parseInt(skillgroup_id) });
    if (skillgroup.length) {
      var group_agents = (skillgroup[0].group_agents).concat("," + user_id).replace(/^[,\s]+|[,\s]+$/g, "").replace(/,[,\s]*,/g, ",");
      await DataBase.db_update(connection, "cs_skillgroup", { group_agents: group_agents }, { id: parseInt(skillgroup_id) });
    }
    array.push(createagent_priority)
    if (array.serverStatus > 1 || array.insertedCount > 0) {
      console.info('Success');
    } else {
      console.info('Server Error');
    }
  }
}

// Function for updating user_priority  created by @Gorla Mahitha
async function updateUsersPriority(obj, _userid) {
  var array = []
  var deleted_data = await DataBase.db_delete(connection, "cs_users_priority", { user_id: parseInt(_userid) })
  for (var i = 1; i < obj.length; i++) {
    var skillgroup_id = decodedJson(obj[i].skillgroup_id)
    var users_priority = decodedJson(obj[i].users_priority)
    if (deleted_data.serverStatus > 1 || deleted_data.acknowledged === true) {
      var updateusers_priorities = await DataBase.db_insert(connection, "cs_users_priority", [{ users_priority: parseInt(users_priority), skillgroup_id: parseInt(skillgroup_id), user_id: parseInt(_userid) }])
      array.push(updateusers_priorities);
      var skillgroup = await DataBase.db_select(connection, "cs_skillgroup", { id: parseInt(skillgroup_id) });   
      var group_agents = (skillgroup[0].group_agents).concat("," + _userid).replace(/^[,\s]+|[,\s]+$/g, "").replace(/,[,\s]*,/g, ",");
      var arr = group_agents.split(',');
      var unique_groupagents = arr.filter(function (value, index, self) {
        return self.indexOf(value) === index;
      }).join(',');
      var addskillgroup = await DataBase.db_update(connection, "cs_skillgroup", { group_agents: unique_groupagents }, { id: parseInt(skillgroup_id) });
      console.info(addskillgroup)

    }
  }
  return array
}

// Update User
app.post('/users/updateuser', verifyToken, async (req, res) => {
  const obj = (req.body)[0];
  var _userId = req.token.userid;
  obj.user_id = parseInt(decodedJson(obj.user_id));
  obj.first_name = decodedJson(obj.first_name);
  obj.role_id = parseInt(decodedJson(obj.role_id));
  obj.last_name = decodedJson(obj.last_name);
  obj.client_id = parseInt(decodedJson(obj.client_id));
  obj.region = decodedJson(obj.region);
  obj.chat_concurrency = decodedJson(obj.chat_concurrency);
  obj.active = 1;
  obj.language = decodedJson(obj.language);
  obj.bot_id = decodedJson(obj.bot_id);
  obj.role_name = decodedJson(obj.role_name);
  obj.login_using = decodedJson(obj.login_using);
  obj.channels = decodedJson(obj.channels);
  var object = { client_id: obj.client_id, role_id: obj.role_id, first_name: obj.first_name, last_name: obj.last_name, chat_concurrency: parseInt(obj.chat_concurrency) }
  var UserUpdateResponse = await DataBase.db_update(connection, "cs_users", object, { id: obj.user_id })
  if (UserUpdateResponse.serverStatus > 1 || UserUpdateResponse.acknowledged === true) {
    await UpdateRolePremission(obj.role_id, obj.user_id);
    await UpdateUserProfiles(obj, obj.user_id);
    await updateUsersPriority(req.body, obj.user_id)
    res.status(200).send({ message: "successfully updated" });
  } else {
    res.status(500).json({ message: "failed" });
  }
});

// update active user
app.post('/users/updateactiveuser', verifyToken, async (req, res) => {
  const obj = (req.body);
  var _userId = req.token.userid;
  var userId = decodedJson(obj.user_id)
  obj.active = decodedJson(obj.active);
  var UserDeleteResponse = await DataBase.db_update(connection, "cs_users", { active: parseInt(obj.active) }, { id: parseInt(userId) })

  if (UserDeleteResponse.serverStatus > 1 || UserDeleteResponse.acknowledged === true) {
    res.status(200).send({ message: "successfully updated" });
  } else {
    res.status(500).send({ message: "failed" });
  }

});

// delete rest api
app.post('/users/deleteall', verifyToken, async (req, res) => {
  const obj = (req.body);
  var _userId = req.token.userid;
  obj.user_id = decodedJson(obj.user_id);
  obj.email = decodedJson(obj.email);
  let UserDeleteResponse = await DataBase.db_delete(connection, "cs_users", { id: parseInt(obj.user_id) });
  if (UserDeleteResponse.serverStatus > 1 || UserDeleteResponse.deletedCount > 0) {
    await deleteUserProfiles(obj);
    res.status(200).json({ message: "successfully deleted" });
  } else {
    res.status(500).json({ message: "failed" });
  }
});

function deleteUserProfiles(obj) {
  return new Promise(async function (resolve, reject) {
    var deleteData = await DataBase.db_delete(connection, "cs_userprofiles", { id: parseInt(obj.user_id) });;
    if (deleteData.serverStatus > 1 || deleteData.deletedCount > 0) {
      resolve(deleteData)
    } else {
      reject('Server Error');
    }
  });
}


//get total user count
app.get('/users/total', verifyToken, async (req, res) => {
  var data = [];
  var obj = {};
  obj['no_of_users'] = await GetUserCount();
  var rolescount = await DataBase.db_select(connection, "cs_roles", {});
  for (var i = 0; i < rolescount.length; i++) {
    obj[(rolescount[i].title.toLowerCase()).replace(/\s/g, "_")] = await OverAllUsersCount(rolescount[i].id)
  }
  data.push(obj)
  res.send(data)
})


// Total Users
async function GetUserCount() {
  var count = await DataBase.db_count(connection, "cs_users", {});
  return count;
}

//OverAllUsersCount
async function OverAllUsersCount(role_id) {
  var OverAllCount = await DataBase.db_count(connection, "cs_users", { role_id: parseInt(role_id) });
  return OverAllCount;
}

//get total statuscount
app.get('/users/statuscount', verifyToken, async (req, res) => {
  var data = []
  var obj = {};
  var StatusCount = await DataBase.db_select(connection, "cs_users", {});
  obj['offline'] = 0;
  obj['available'] = 0;
  obj['away'] = 0;
  obj['busy'] = 0;
  obj['in_a_call'] = 0;
  for (var i = 0; i < StatusCount.length; i++) {
    var statusName = '';
    switch (StatusCount[i].agent_status) {
      case 0:
        statusName = 'busy';
        break;
      case 1:
        statusName = 'available';
        break;
      case 2:
        statusName = 'away';
        break;
      case 3:
        statusName = 'in_a_call';
        break;
      case -1:
        statusName = 'offline'
    }
    obj[statusName] = await AgentStatusCount(StatusCount[i].agent_status)
  }
  data.push(obj)
  res.send(data)
})

//AgentStatusCount
async function AgentStatusCount(agent_status) {
  var StatusCount = await DataBase.db_count(connection, "cs_users", { agent_status: parseInt(agent_status) });
  return StatusCount;
}

//Active agents details
app.get('/users/active', verifyToken, async (req, res, err) => {
  let userObjectList = await DataBase.db_select(connection, "cs_users", { active: 1, role_id: 4 });
  for (var i = 0; i < userObjectList.length; i++) {
    var upList = await DataBase.db_select(connection, "cs_userprofiles", { user_id: userObjectList[i].id });
    for (let j = 0; j < upList.length; j++) {
      var _key = upList[j].profile_key;
      if (_key === 'channels') {
        userObjectList[i][_key] = upList[j].profile_value;
      }
    }
  }
  res.status(200).send(userObjectList)
});

//Get user emails    
app.get('/users/emails', verifyToken, async (req, res) => {
  var UserEmailobjectList = await DataBase.db_select(connection, "cs_users", {});
  res.status(200).send(UserEmailobjectList)
});


// send email for kb articles
app.post('/kbarticles/sendemail', (req, res) => {
  var Link = decodedJson(req.body.Link);
  var Tomail = decodedJson(req.body.Tomail);
  var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'kbarticlessendemail@gmail.com',
      pass: 'ntfx qtyp piaf sugl'
    }
  });
  var mailOptions = {
    from: 'kbarticlessendemail@gmail.com',
    to: Tomail,
    subject: 'ConverSense KB Articles Link',
    html: "Kb articles link is " + Link + ""
  };
  transporter.sendMail(mailOptions, function (error, info) {
    if (error) {
      res.status(400).json({ message: 'Failed' })
    } else {
      res.status(200).json({ message: 'Email sent successfully' });
    }
  })
});


/* GET Single user object */
app.get('/users/user/:id', verifyToken, async (req, res, next) => {
  var _userId = req.params.id;
  const ModifyResults = [];
  let userObjectList = await DataBase.db_select(connection, "cs_users", { id: parseInt(_userId) });
  var upList = await DataBase.db_select(connection, "cs_userprofiles", { user_id: userObjectList[0].id });
  var users_prioritylist = await DataBase.db_select(connection, "cs_users_priority", { user_id: parseInt(_userId) })
  // console.log(users_prioritylist)
  for (let j = 0; j < upList.length; j++) {
    var _key = upList[j].profile_key;
    if (_key !== 'active') {
      userObjectList[0][_key] = upList[j].profile_value
    }
  }
  ModifyResults.push(userObjectList[0])
  for (var i = 0; i < users_prioritylist.length; i++) {
    ModifyResults.push({ ...users_prioritylist[i] })
  }

  res.send(ModifyResults)
});


app.post('/dashboard/agentproductivity', verifyToken, async (req, res) => {
  var startdate = decodedJson(req.body.startdate);
  var enddate = decodedJson(req.body.enddate);
  var array = [];
  var count;
  var user_details = [];
  if (startdate === '0000-00-00' && enddate === '0000-00-00') {
    startdate = moment().format('YYYY-MM-DD ').concat('00:00:01')
    enddate = moment().format('YYYY-MM-DD HH:mm:ss')
  } else {
    startdate = startdate.concat(' 00:00:01')
    enddate = enddate.concat(' 23:59:59')
  }
  var user_data = await DataBase.db_select(connection, "cs_users", { role_id: 4 })
  var avgtime_insec;
  var totalSec = 0
  var hours = 0
  var minutes = 0
  var seconds = 0
  for (var i = 0; i < user_data.length; i++) {
    var sessiondata = await DataBase.db_select(connection, "chat_sessions", { agent_id: user_data[i].id, is_agent_routing: 1, chat_initiated_on: { $gte: startdate, $lt: enddate } })
    if (sessiondata.length) {
      count = await DataBase.db_count(connection, "chat_sessions", { agent_id: user_data[i].id, is_agent_routing: 1, chat_initiated_on: { $gte: startdate, $lt: enddate } })
      user_data[i].total_calls_handled = count;
      for (var j = 0; j < sessiondata.length; j++) {
        if (sessiondata[j].chatduration_byagent !== undefined && sessiondata[j].chatduration_byagent !== null) {
          hours += parseInt((sessiondata[j].chatduration_byagent).substring(0, 2))
          minutes += parseInt((sessiondata[j].chatduration_byagent).substring(3, 5))
          seconds += parseInt((sessiondata[j].chatduration_byagent).substring(6))
        }
      }
      user_data[i].Avg_calls_handled = user_data[i].avg_handle_time;
      totalSec += hours * 60 * 60
      totalSec += minutes * 60
      totalSec += seconds
      avgtime_insec = Math.round(totalSec / count)
      const avghandletime = new Date(avgtime_insec * 1000).toISOString().slice(11, 19);
      user_data[i].average_handled_time = avghandletime
      await DataBase.db_update(connection, "cs_users", { total_count: count, avg_handle_time: user_data[i].average_handled_time }, { id: user_data[i].id })
      if (user_data[i].total_calls_handled > 0) {
        user_details.push({ ...user_data[i] })
      }
    }
  }
  var response = user_details;
  if (!response.length) {
    res.status(200).json({ message: "  agentproductivity is empty " });
  }
  else {
    var date = moment().format("YYYY-MM-DD HH:mm:ss");
    response.forEach((el) => {
      if (el.end_time === '0000-00-00 00:00:00') {
        array.push({ agent_name: el.name, total_calls_handled: el.total_calls_handled, idle_time: '', total_calls_transfered: '0', missed_calls: '0', average_handled_time: el.average_handled_time })
      }
      else {
        var ideletime = ((new Date(date) - new Date(el.end_time)));
        var ideletimeinsec = ideletime / (1000);
        var ideletimeresult = new Date(ideletimeinsec * 1000).toISOString().slice(11, 19);
        array.push({ agent_name: el.name, total_calls_handled: el.total_calls_handled, idle_time: ideletimeresult, total_calls_transfered: '0', missed_calls: '0', average_handled_time: el.average_handled_time })
      }
    })
    res.status(200).send(array);
  }
})
app.get('/dashboard/livesession', verifyToken, async (req, res) => {
  var array = []
  var response;
  var s_response = [];
  var fromDate = moment().format('YYYY-MM-DD ').concat('00:00:01')
  var toDate = moment().format('YYYY-MM-DD HH:mm:ss')
  var condition1 = { is_agent_routing: 1, chat_status: { $in: [3, 4] }, self_service_completed_on: { $gte: fromDate, $lt: toDate } }
  var response1 = await DataBase.db_select(connection, "chat_sessions", condition1);
  for (var i = 0; i < response1.length; i++) {
    var response2 = await DataBase.db_select(connection, "chat_customers", { id: parseInt(response1[i].customer_id) });
    var response3 = await DataBase.db_select(connection, "cs_users", { id: parseInt(response1[i].agent_id) })
    for (var j = 0; j < response2.length; j++) {
      for (var k = 0; k < response3.length; k++) {
        response1[i].name = response3[k].name;
      }
      response1[i].first_name = response2[j].first_name;
      response1[i].last_name = response2[j].last_name
    }
    s_response.push({
      agentanswered_time: response1[i].agentanswered_time, user_firstmessage: response1[i].user_firstmessage,
      first_name: response1[i].first_name, last_name: response1[i].last_name, name: response1[i].name, bot_id: response1[i].bot_id,
      sentiment_result: response1[i].sentiment_result, chat_status: response1[i].chat_status, agent_skill_group: response1[i].skillgroup_name, ticket_id: response1[i].ticket_number
    })
  }
  response = s_response;
  var serialnum = 0
  if (!response.length) {
    res.status(200).json({ message: " live agent is empty " });
  }
  else {
    response.forEach(el => {
      serialnum += 1;
      var customersname = el.first_name + ' ' + el.last_name;
      if (customersname === null) {
        array.push({ s_no: serialnum, customer_name: '', Query: decodedJson(el.user_firstmessage), Sentiment_score: el.sentiment_result, Session_status: el.chat_status, Agent_name: el.name, Agent_skill_level: '0', Skill_group: el.agent_skill_group, chat_duration: el.agentanswered_time, current_ticket: el.ticket_id, Routing_bot: el.bot_id })
      }
      else {
        var chat_status;
        if (parseInt(el.chat_status) === 3) {
          chat_status = 'Self Service Completed';
        } else {
          chat_status = 'Agent HandOff';
        }
        if ((parseInt(el.chat_status) === 3 || parseInt(el.chat_status) === 4)) {
          array.push({ s_no: serialnum, customer_name: customersname, Query: decodedJson(el.user_firstmessage), Sentiment_score: el.sentiment_result, Session_status: chat_status, Agent_name: el.name, Agent_skill_level: '0', Skill_group: el.agent_skill_group, chat_duration: el.agentanswered_time, current_ticket: el.ticket_id, Routing_bot: el.bot_id })
        }
      }
    });
    console.log(array)
    res.status(200).send(array)
  }
})

//live session ends

// import Rest Api start
app.post('/users/exports', async (req, res) => {
  const obj = (req.body);
  var objlength = obj.length;
  var array = [];
  var errormessage = [];
  var object = [];
  var totalinsertedrows = [];
  var i = 0;
  while (i < objlength) {
    obj.email = decodedJson(obj[i].email);
    obj.first_name = decodedJson(obj[i].first_name);
    obj.last_name = decodedJson(obj[i].last_name);
    obj.name = obj.first_name + ' ' + obj.last_name;
    obj.client_id = 1;
    obj.role_id = parseInt(decodedJson(obj[i].role_id));
    obj.date = decodedJson(obj[i].date);
    obj.region = decodedJson(obj[i].region);
    obj.channels = decodedJson(obj[i].channels);
    obj.chat_conccurency = decodedJson(obj[i].chat_conccurency);
    obj.active = 1;
    obj.password = 'Sensiple@123';
    var dbPassword = encryptedJson(obj.password);
    obj.language = decodedJson(obj[i].language);
    obj.bot_id = decodedJson(obj[i].bot_id);
    obj.role_name = decodedJson(obj[i].role_name);
    obj.login_using = decodedJson(obj[i].login_using);
    const createSchema = Joi.object().keys({
      email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com'] } }),
      first_name: Joi.string().required(),
      last_name: Joi.string().required(),
      role_id: Joi.required(),
      region: Joi.string().required(),
      role_name: Joi.string().required()
    });
    var validate = createSchema.validate({ email: obj.email, first_name: obj.first_name, last_name: obj.last_name, role_id: obj.role_id, role_name: obj.role_name, region: obj.region });
    if (validate.error) {
      var validateerror = validate.error;
      errormessage.push(validateerror);
      array.push(obj[i]);
    }
    else {
      object.push(obj[i]);
    }
    i++;
  }
  var j = 0;
  while (j < object.length) {
    object.email = decodedJson(object[j].email);
    object.first_name = decodedJson(object[j].first_name);
    object.last_name = decodedJson(object[j].last_name);
    object.name = object.first_name + ' ' + object.last_name;
    object.client_id = '1';
    object.role_id = decodedJson(object[j].role_id);
    object.date = decodedJson(object[j].date);
    object.region = decodedJson(object[j].region);
    object.channels = decodedJson(object[j].channels);
    object.chat_conccurency = decodedJson(object[j].chat_conccurency);
    object.active = 1;
    object.password = 'Sensiple@123';
    var dbPassword = encryptedJson(object.password);
    object.language = decodedJson(object[j].language);
    object.bot_id = decodedJson(object[j].bot_id);
    object.role_name = decodedJson(object[j].role_name);
    object.login_using = decodedJson(object[j].login_using);

    var Object = { name: object.name, email: object.email, is_temp_password: 1, password: dbPassword, client_id: object.client_id, role_id: object.role_id, agent_status: 1, first_name: object.first_name, last_name: object.last_name, created_date: object.date, active: object.active }
    var response = await DataBase.db_insert(connection, "cs_users", [Object]);
    object.userid = response.insertId;
    if (response.serverStatus > 1 && response.insertId > 0 || response.insertedCount > 0) {
      await CreateUserProfiles(object);
      newaccountsendemail(object.role_id, object.email)
    }
    totalinsertedrows.push(response);
    j++;
  }
  res.status(200).json([{ "totalobjlength": objlength, "sumoftotalaffectedrows": totalinsertedrows.length, "validationerrorobjcount": array.length, "errormessage": errormessage }]);
});

//Store banner meassge based on the skillgroup  by admin --created by Lokeshwari--start
app.post('/bannermessage', verifyToken, async (req, res) => {
  const obj = (req.body);
  var objlength = obj.length;
  var array = [];
  var i = 0;
  while (i < objlength) {
    var flag = decodedJson(obj[i].flag);
    var bannerMessage = obj[i].bannermessage;
    var bannermsgfromdatetime = decodedJson(obj[i].bannermsgfromdatetime);
    var bannermsgtodatetime = decodedJson(obj[i].bannermsgtodatetime);
    var timezone = obj[i].timezonename
    var skillGroupName = obj[i].skillgroup.split(",");
    var results;
    var response;
    if (parseInt(flag) === 1) {
      var response = await DataBase.db_select(connection, "cs_skillgroup", {})
      for (let j = 0; j < skillGroupName.length; j++) {
        for (let r = 0; r < response.length; r++) {
          var decodedSkillGroupName = decodedJson(response[r].name);
          var skillName = decodedJson(skillGroupName[j]);
          if (skillName.trim() === decodedSkillGroupName.trim()) {
            var results = await DataBase.db_insert(connection, "cs_pushnotification", [{ skillgroup_id: response[r].id, bannerMessage: bannerMessage, bannermsgfromdatetime: bannermsgfromdatetime, bannermsgtodatetime: bannermsgtodatetime, timezone: timezone, active: 1 }])
            array.push(results)
          }
        }
      }
    }
    else if (parseInt(flag) === 0) {
      var getdata = await DataBase.db_select(connection, "cs_skillgroup", {});
      for (let g = 0; g < getdata.length; g++) {
        var skilid = getdata[g].id
        response = await DataBase.db_select(connection, "cs_pushnotification", { skillgroup_id: parseInt(skilid) })
        for (let l = 0; l < response.length; l++) {
          for (let j = 0; j < skillGroupName.length; j++) {
            if (decodedJson(getdata[g].name) === decodedJson(skillGroupName[j]) && decodedJson(response[l].bannerMessage) === decodedJson(bannerMessage)) {
              results = await DataBase.db_update(connection, "cs_pushnotification", { active: 0 }, { id: response[l].id })
              array.push(results)
            }
          }
        }
      }
    }
    i++
  }
  res.send(array)
});

app.post("/profanitycheckconfiguration", verifyToken, async (req, res) => {
  const headersApi = {
    "x-api-key": "AIzaSyAuB1-ucvN5PT74_tAmCFj2opJOVNAm_Yw"
  };
  var data = {
    header: {
      clientId: "Conversense",
      botId: "jeniehealth-bot",
      apiName: "ProfanityCheckConfiguration"
    },
    body: {
      profaneBenchmark: 50
    }
  };
  if (data != null) {
    await axios.post("https://intelisense-qa-61hxkuel.uc.gateway.dev/ProfanityCheckConfiguration", data, {
      headers: headersApi
    }).then((response) => {
      if (response.data.header.responseMessage === "Successfully updated the existing config values") {
        res.status(200).json({ message: "Successfully updated the existing config values" });
      }
    });
  }
});

app.get("/intelisenseconfiguration", verifyToken, async (req, res) => {
  var array = []
  var intelisenseConfig = await DataBase.db_select(connection, "is_configuration");
  for (let i = 0; i < intelisenseConfig.length; i++) {
    array.push({ apiname: intelisenseConfig[i].api_name, enable: intelisenseConfig[i].enable })
  }
  res.status(200).send(array)
})



app.post("/intelisenseconfig/profanity", verifyToken, async (req, res) => {
  var _userId = req.token.userid;
  var insertData;
  var api_Name = decodedJson(req.body.apiname);
  var bot_Id = decodedJson(req.body.botid);
  var skillgroup_id = decodedJson(req.body.skillgroup);
  var recipient = (decodedJson(req.body.recipients)).split(",");
  var insertData = await DataBase.db_select(connection, "is_configuration", { api_name: api_Name });
  if (insertData.length) {
    insertData = await DataBase.db_update(connection, "is_configuration", { bot_id: bot_Id, skillgroup_id: skillgroup_id, recipients: recipient, date: moment().format("YYYY-MM-DD hh:mm:ss"), admin_id: _userId }, { api_name: api_Name });
  }
  else {
    insertData = await DataBase.db_insert(connection, "is_configuration", [{ api_name: api_Name, bot_id: bot_Id, skillgroup_id: skillgroup_id, recipients: recipient, date: moment().format("YYYY-MM-DD hh:mm:ss"), admin_id: _userId }]);
  }
  res.status(200).send(insertData);
});


app.post("/bestagentsuggestconfiguration", verifyToken, async (req, res) => {
  var _userId = req.token.userid;
  var api_name = decodedJson(req.body.api_name)
  var sentimentBenchmark = decodedJson(req.body.sentiment);
  var agentProfanityBenchmark = decodedJson(req.body.agentprofanity);
  var previousCallDurationInSeconds = decodedJson(req.body.previousCallDuration);
  var customerCallbackWithInSeconds = decodedJson(req.body.customerCallback);
  var noOfAgentsToSuggest = decodedJson(req.body.noOfAgentsToSuggest);
  var header = {
    clientId: "Conversense",
    botId: "jeniehealth-bot",
    apiName: "BestAgentSuggestConfiguration"
  };
  console.log("get", req.body)
  var body = {
    sentimentScoreBenchmark: sentimentBenchmark,
    agentProfanityBenchmark: agentProfanityBenchmark,
    previousCallDurationInSeconds: previousCallDurationInSeconds,
    customerCallbackWithInSeconds: customerCallbackWithInSeconds,
    noOfAgentsToSuggest: noOfAgentsToSuggest
  };
  const headersApi = {
    "x-api-key": "AIzaSyAuB1-ucvN5PT74_tAmCFj2opJOVNAm_Yw"
  };
  var data = {
    header: header,
    body: body
  };
  if (sentimentBenchmark != null) {
    axios.post("https://intelisense-qa-61hxkuel.uc.gateway.dev/BestAgentSuggestConfiguration", data, {
      headers: headersApi
    }).then(async (res) => {
      console.log("res.data.header.responseMessage", res.data.header.responseMessage)
      if (res.data.header.responseMessage === "Successfully updated the existing config values") {
        var is_configuration = await DataBase.db_select(connection, "is_configuration", { api_name: api_name });
        if (is_configuration.length) {
          await DataBase.db_update(connection, "is_configuration", { sentimentscore_benchmark: sentimentBenchmark, agentprofanity_benchmark: agentProfanityBenchmark, previous_calldurationin_seconds: previousCallDurationInSeconds, customer_callback_inseconds: customerCallbackWithInSeconds, noofagents_tosuggest: noOfAgentsToSuggest, date: moment().format("YYYY-MM-DD hh:mm:ss"), admin_id: _userId }, { api_name: api_name });
        }
        else {
          await DataBase.db_insert(connection, "is_configuration", [{ api_name: api_name, sentimentscore_benchmark: sentimentBenchmark, agentprofanity_benchmark: agentProfanityBenchmark, previous_calldurationin_seconds: previousCallDurationInSeconds, customer_callback_inseconds: customerCallbackWithInSeconds, noofagents_tosuggest: noOfAgentsToSuggest, date: moment().format("YYYY-MM-DD hh:mm:ss"), admin_id: _userId }]);

        }
      }
    });
  }
  res.status(200).json({ message: "Successfully updated the existing config values" });
});



app.post("/chatsessionterminationconfiguration", verifyToken, async (req, res) => {
  var userStartSessionMessageCount = decodedJson(req.body.userStartSessionMessageCount);
  var userEndSessionMessageCount = decodedJson(req.body.userEndSessionMessageCount);
  const headersApi = {
    "x-api-key": "AIzaSyAuB1-ucvN5PT74_tAmCFj2opJOVNAm_Yw"
  };
  var data = {
    header: {
      clientId: "Conversense",
      botId: "jeniehealth-bot",
      apiName: "ChatSessionTerminatedConfiguration"
    },
    body: {
      userStartSessionMessageCount: userStartSessionMessageCount,
      userEndSessionMessageCount: userEndSessionMessageCount,
      piiFlag: false,
      sentEntities: false
    }
  };
  if (data != null) {
    await axios.post("https://intelisense-qa-61hxkuel.uc.gateway.dev/ChatSessionTerminatedConfiguration ", data, {
      headers: headersApi
    }).then(async (response) => {
      if (response.data.header.responseMessage === "Successfully updated the existing config values") {
        res.status(200).json({ message: "Successfully updated the existing config values" });
      }
    });
  }
});

app.post("/enablefcr", async (req, res) => {
  var flag = decodedJson(req.body.flag);
  var id = decodedJson(req.body.id);
  var fcr_List = await DataBase.db_select(connection, "is_configuration", { admin_id: parseInt(id), api_name: "firstcallresolution" });
  if (fcr_List.length === 0) {
    var insert_fcr = await DataBase.db_insert(connection, "is_configuration", [{ enable: parseInt(flag), admin_id: parseInt(id), api_name: "firstcallresolution" }]);
    if (insert_fcr.serverStatus > 1 || insert_fcr.insertedCount > 0) {
      res.status(200).send({ message: "success" });
    } else {
      res.status(500).send({ message: "failed" });
    }
  } else {
    var update_fcr = await DataBase.db_update(connection, "is_configuration", { enable: parseInt(flag) }, { api_name: "firstcallresolution" });
    if (update_fcr.serverStatus > 1 || update_fcr.acknowledged === true) {
      res.status(200).send({ message: "successfully updated" });
    } else {
      res.status(500).send({ message: "failed" });
    }
  }
});

app.post("/intelisense/enable", verifyToken, async (req, res) => {
  var _userId = req.token.userid;
  var flag = decodedJson(req.body.flag);
  var api_Name = decodedJson(req.body.apiname);
  var enableresults = await DataBase.db_update(connection, "is_configuration", { enable: parseInt(flag) }, { admin_id: _userId, api_name: api_Name });
  res.status(200).send(enableresults);
});

app.get('/', (req, res) => {
  res.send("Welcome to Conversense Admin Console Rest API")
})


//Localdevelopment Enabled Below Line
app.listen(9000)
console.log('Server listening on port at 9000');


//Live Deployment Code Disable while local
// exports.adminConsole = app