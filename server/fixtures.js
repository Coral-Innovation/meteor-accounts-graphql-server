import { Random } from "meteor/random";

export const email = "test@example.com";
export const password = "testtest";
export const loginToken = Random.secret();

if (Meteor.users.find().count() === 0) {
  const userId = Accounts.createUser({ email, password });
  Meteor.users.update(userId, { $set: { 
    "services.resume.loginTokens": [
      {
        hashedToken: Accounts._hashLoginToken(loginToken),
        when: new Date()
      }
    ]
  }});
}
