import { createApolloServer } from "meteor/apollo";
import { Random } from "meteor/random";

const bcrypt = require("bcryptjs");
import { GraphQLDateTime } from "graphql-iso-date";
import { makeExecutableSchema } from "graphql-tools";

const typeDefs = `
  scalar Date

  input HashedPassword {
    algorithm: String!
    digest: String!
  }

  type LoginResponse {
    userId: ID!
    loginToken: String!
    loginTokenExpires: Date!
  }

  type Mutation {
    changePassword(loginToken: String!, oldPassword: HashedPassword!, newPassword: HashedPassword!): Boolean
    createUser(email: String!, password: HashedPassword!): LoginResponse
    loginWithPassword(email: String!, password: HashedPassword!): LoginResponse
    logout(loginToken: String!): Boolean
    resetPassword(resetToken: String!, newPassword: HashedPassword!): Boolean
    resetToken(email: String!): String!
  }

  type Query {
    ping: String
  }
`;

// Inspiration for resolvers:
// https://github.com/davidyaha/apollo-accounts-server/blob/master/server/imports/models/user-account.js
// https://github.com/stubailo/meteor-rest/blob/devel/packages/rest-accounts-password/rest-login.js
// https://github.com/meteor/meteor/blob/master/packages/accounts-password/password_server.js

// Meteor accounts-base retrieves the loginToken from the current LiveData connection.
// Since we don't use this, we need to provide the loginToken as an argument.

const resolvers = {
  Date: GraphQLDateTime,
  Mutation: {
    changePassword(obj, { loginToken, oldPassword, newPassword }) {
      const hashedToken = Accounts._hashLoginToken(loginToken);
      const user = Meteor.users.findOne({
        "services.resume.loginTokens.hashedToken": hashedToken
      });
      if (!user) {
        throw new Error("Couldn't find user");
      }

      const { error } = Accounts._checkPassword(user, oldPassword);
      if (error) {
        throw new Error("Old password incorrect");
      }

      const hash = bcrypt.hashSync(newPassword.digest, 10);
      Meteor.users.update(user._id, {
        // Remove deprecated tokens
        $pull: {
          "services.resume.loginTokens": { hashedToken: { $ne: hashedToken } }
        },
        // Update password
        $set: { "services.password.bcrypt": hash },
        // Avoid conflicts with password reset
        $unset: { "services.password.reset": 1 }
      });

      return true;
    },
    createUser(obj, { email, password }) {
      const userId = Accounts.createUser({ email, password });
      return newLoginToken(userId);
    },
    loginWithPassword(obj, { email, password }) {
      const user = Accounts.findUserByEmail(email);
      if (!user) {
        throw new Error("Couldn't find user.");
      }

      const { userId, error } = Accounts._checkPassword(user, password);
      if (error) {
        throw new Error(error);
      }

      return newLoginToken(userId);
    },
    logout(obj, { loginToken }) {
      const hashedToken = Accounts._hashLoginToken(loginToken);
      const user = Meteor.users.findOne({
        "services.resume.loginTokens.hashedToken": hashedToken
      });
      if (!user) {
        throw new Error("Couldn't find user");
      }

      const matched = Meteor.users.update(user._id, {
        $pull: { "services.resume.loginTokens": { hashedToken } }
      });

      return matched === 1;
    },
    resetPassword(obj, { resetToken, newPassword }) {
      const user = Meteor.users.findOne({
        "services.password.reset.token": resetToken
      });
      if (!user) {
        throw new Error("Couldn't find user associated with reset token");
      }

      // Although the documentation says that `setPassword`
      // expects the `newPassword` parameter to be a string, it
      // also works with a hashed password
      try {
        Accounts.setPassword(user._id, newPassword);
        return true;
      } catch (err) {
        console.log(err);
        return false;
      }
    },
    resetToken(obj, { email }) {
      const user = Accounts.findUserByEmail(email);
      if (!user) {
        throw new Error("Couldn't find user");
      }

      const { token } = Accounts.generateResetToken(user._id, email, "reset");
      return token;
    }
  },
  Query: {
    ping: () => "pong"
  }
};

const schema = makeExecutableSchema({
  resolvers,
  typeDefs
});

createApolloServer({
  schema
});

function newLoginToken(userId) {
  const token = Random.secret();
  const when = new Date();
  Accounts._insertLoginToken(userId, { token, when });

  // Return according to LocalStorage keys "Meteor.userId", "Meteor.loginToken", "Meteor.loginTokenExpires"
  return {
    loginToken: token,
    loginTokenExpires: Accounts._tokenExpiration(when),
    userId
  };
}
