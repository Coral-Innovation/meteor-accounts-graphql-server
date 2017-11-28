import fetch from "node-fetch";
import assert from "assert";
import crypto from "crypto";

import { password, email } from "./fixtures";

const hash = crypto.createHash("sha256");
const oldPassword = {
  algorithm: "sha-256",
  digest: hash.update(password).digest("hex")
};
const userId = Accounts.findUserByEmail(email)._id;

describe("Schema", function() {
  describe("Mutations", function() {
    describe("changePassword", function() {
      describe("userId not known", function() {
        it("should throw an error", function(done) {
          const mutation = `mutation {
            changePassword(
              userId: "foobar", 
              oldPassword: { algorithm: "foo", digest: "bar" }, 
              newPassword: { algorithm: "foo", digest: "bar" }
            )
          }`;
          fetch("http://localhost:3000/graphql", { 
            method: "POST", 
            body: JSON.stringify({ query: mutation }), 
            headers: { "Content-Type": "application/json" } 
          }).then((res) => res.json())
            .then((json) => done(assert.equal(json.errors[0].message, "Couldn't find user")))
            .catch((err) => done(err));
        });
      });

      describe("Old password incorrect", function() {
        it("should throw an error", function(done) {
          const mutation = `mutation {
            changePassword(
              userId: "${userId}",
              oldPassword: { algorithm: "${oldPassword.algorithm}", digest: "foo"}
              newPassword: { algorithm: "${oldPassword.algorithm}", digest: "bar"}
            )
          }`;
          fetch("http://localhost:3000/graphql", { 
            method: "POST", 
            body: JSON.stringify({ query: mutation }), 
            headers: { "Content-Type": "application/json" } 
          }).then((res) => res.json())
            .then((json) => done(assert.equal(json.errors[0].message, "Old password incorrect")))
            .catch((err) => done(err));
        });
      });

      describe("New password is empty string", function() {
        it("should throw an error", function() {
          const mutation = `mutation {
            changePassword(
              userId: "${userId}",
              oldPassword: { algorithm: "${oldPassword.algorithm}", digest: "${oldPassword.digest}"}
              newPassword: { algorithm: "${oldPassword.algorithm}", digest: "  "}
            )
          }`;
          fetch("http://localhost:3000/graphql", { 
            method: "POST", 
            body: JSON.stringify({ query: mutation }), 
            headers: { "Content-Type": "application/json" } 
          }).then((res) => res.json())
            .then((json) => done(assert.equal(json.errors[0].message, "Couldn't hash password")))
            .catch((err) => done(err));
        });
      });

      describe("changed successfully", function() {
        it("should return true", function() {
          const mutation = `mutation {
            changePassword(
              userId: "${userId}",
              oldPassword: { algorithm: "${oldPassword.algorithm}", digest: "${oldPassword.digest}"}
              newPassword: { algorithm: "${oldPassword.algorithm}", digest: "1982uakjnsdau8u21knasd"}
            )
          }`;
          fetch("http://localhost:3000/graphql", { 
            method: "POST", 
            body: JSON.stringify({ query: mutation }), 
            headers: { "Content-Type": "application/json" } 
          }).then((res) => res.json())
            .then((json) => done(assert.equal(json.data.changePassword, true)))
            .catch((err) => done(err));
        });
      });
    });
  });

  describe("Queries", function() {
    describe("Ping", function() {
      it("should return 'Pong'", function(done) {
        const query = "{ping}";
        fetch(`http://localhost:3000/graphql?query=${query}`)
          .then((res) => res.json())
          .then((json) => { 
            assert(json.data.ping === "pong");
            done();
          })
          .catch((err) => { throw err; });
      });
    });
  });
});
