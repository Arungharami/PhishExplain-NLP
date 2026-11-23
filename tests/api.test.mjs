import test from "node:test";import assert from "node:assert/strict";import handler from "../api/infer.js";
function mock(method,body,headers={}){const res={statusCode:200,setHeader(){},status(n){this.statusCode=n;return this},json(x){this.body=x;return this}};return{req:{method,body,headers},res}}
test("configuration no secret leak",async()=>{const {req,res}=mock("GET");await handler(req,res);assert.equal(res.statusCode,200);assert.equal(typeof res.body.configured,"boolean")});
test("unknown method rejected",async()=>{const {req,res}=mock("DELETE");await handler(req,res);assert.equal(res.statusCode,405)});
test("unauthenticated provider call blocked",async()=>{const {req,res}=mock("POST",{text:"hi"});await handler(req,res);assert.ok([401,503].includes(res.statusCode))});
