
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const { v4: uuid } = require('uuid');
const { BlobServiceClient } = require('@azure/storage-blob');
const { CosmosClient } = require('@azure/cosmos');

const app = express();
app.use(cors());
app.use(express.json());
const upload = multer();

const blobService = BlobServiceClient.fromConnectionString(process.env.BLOB_CONNECTION_STRING);
const blobContainer = blobService.getContainerClient(process.env.BLOB_CONTAINER);

const cosmos = new CosmosClient({
  endpoint: process.env.COSMOS_ENDPOINT,
  key: process.env.COSMOS_KEY
});
const db = cosmos.database(process.env.COSMOS_DB);
const container = db.container(process.env.COSMOS_CONTAINER);

function auth(req,res,next){
  const h=req.headers.authorization;
  if(!h) return res.sendStatus(401);
  try{
    req.user=jwt.verify(h.split(' ')[1],process.env.JWT_SECRET);
    next();
  }catch{
    res.sendStatus(403);
  }
}

// Register
app.post('/api/register', async (req,res)=>{
  const {name,email,password,role}=req.body;
  const {resources}=await container.items.query({
    query:"SELECT * FROM c WHERE c.type='user' AND c.email=@e",
    parameters:[{name:"@e",value:email}]
  }).fetchAll();
  if(resources.length) return res.status(400).json({error:"User exists"});

  await container.items.create({
    id:uuid(),
    type:"user",
    name,email,role,
    password:await bcrypt.hash(password,10)
  });
  res.json({message:"Registered"});
});

// Login
app.post('/api/login', async (req,res)=>{
  const {email,password}=req.body;
  const {resources}=await container.items.query({
    query:"SELECT * FROM c WHERE c.type='user' AND c.email=@e",
    parameters:[{name:"@e",value:email}]
  }).fetchAll();
  const user=resources[0];
  if(!user||!(await bcrypt.compare(password,user.password)))
    return res.status(401).json({error:"Invalid credentials"});

  const token=jwt.sign({id:user.id,role:user.role,name:user.name},process.env.JWT_SECRET);
  res.json({token,role:user.role});
});

// Upload
app.post('/api/photos',auth,upload.single('image'),async(req,res)=>{
  if(req.user.role!=='creator') return res.sendStatus(403);
  const blobName=`${uuid()}-${req.file.originalname}`;
  const blob=blobContainer.getBlockBlobClient(blobName);
  await blob.uploadData(req.file.buffer,{blobHTTPHeaders:{blobContentType:req.file.mimetype}});

  const photo={
    id:uuid(),
    type:"photo",
    url:blob.url,
    title:req.body.title,
    creator:req.user.name,
    reactions:{like:0,love:0,wow:0,sad:0},
    comments:[],
    shares:0
  };
  await container.items.create(photo);
  res.json(photo);
});

// Feed
app.get('/api/photos',async(req,res)=>{
  const {resources}=await container.items.query("SELECT * FROM c WHERE c.type='photo' ORDER BY c._ts DESC").fetchAll();
  res.json(resources);
});

// React
app.post('/api/photos/:id/react/:type',auth,async(req,res)=>{
  const {resource}=await container.item(req.params.id,req.params.id).read();
  resource.reactions[req.params.type]++;
  await container.items.upsert(resource);
  res.json(resource.reactions);
});

// Comment
app.post('/api/photos/:id/comment',auth,async(req,res)=>{
  const {resource}=await container.item(req.params.id,req.params.id).read();
  resource.comments.push({user:req.user.name,text:req.body.text});
  await container.items.upsert(resource);
  res.json(resource.comments);
});

// Share
app.post('/api/photos/:id/share',auth,async(req,res)=>{
  const {resource}=await container.item(req.params.id,req.params.id).read();
  resource.shares++;
  await container.items.upsert(resource);
  res.json({shares:resource.shares});
});

const PORT=process.env.PORT||3000;
app.listen(PORT,()=>console.log(`SnapFlow AZURE running on port ${PORT}`));
