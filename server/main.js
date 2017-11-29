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
    changePassword(userId: String!, oldPassword: HashedPassword!, newPassword: HashedPassword!): Boolean
    loginWithPassword(email: String!, password: HashedPassword!): LoginResponse
    logout(userId: String!, loginToken: String!): Boolean
  }

  type Query {
    ping: String
  }
`;

// Inspiration for resolvers: 
// https://github.com/davidyaha/apollo-accounts-server/blob/master/server/imports/models/user-account.js
// https://github.com/stubailo/meteor-rest/blob/devel/packages/rest-accounts-password/rest-login.js
// https://github.com/meteor/meteor/blob/master/packages/accounts-password/password_server.js

const resolvers = {
  Date: GraphQLDateTime,
  Mutation: {
    changePassword: (obj, { userId, oldPassword, newPassword }) => {
      const user = Meteor.users.findOne(userId);
      if (!user) {
        throw new Error("Couldn't find user");
      }

      const { error } = Accounts._checkPassword(user, oldPassword);
      if (error) {
        throw new Error("Old password incorrect");
      }

      const hash = bcrypt.hashSync(newPassword.digest, 10);
      Meteor.users.update(userId, {
        $set: { "services.password.bcrypt": hash },
        $unset: { "services.password.reset": 1 }  // Avoid conflicts with password reset
      });

      return true;
    },
    loginWithPassword: (obj, { email, password }, context) => {
      const user = Accounts.findUserByEmail(email);
      if (!user) {
        throw new Error("Couldn't find user.");
      }
      
      const { userId, error } = Accounts._checkPassword(user, password);
      if (error) {
        throw new Error(error);
      }
      
      const token = Random.secret();
      const when = new Date();
      Accounts._insertLoginToken(user._id, { token, when });

      // Return according to LocalStorage keys "Meteor.userId", "Meteor.loginToken", "Meteor.loginTokenExpires"
      return {
        userId: user._id,
        loginToken: token,
        loginTokenExpires: Accounts._tokenExpiration(when)
      };
    },
    // Meteor accounts-base retrieves the loginToken and userId from the current LiveData connection.
    // Since we don't use this, we need to provide the loginToken and userId as arguments.
    logout: (obj, { userId, loginToken }) => {
      const hashedToken = Accounts._hashLoginToken(loginToken);
      const matched = Meteor.users.update(userId, {
        $pull: {  "services.resume.loginTokens": { hashedToken } }
      });

      return matched === 1;
    }
  },
  Query: {
    ping: () => "pong"
  }
};

const schema = makeExecutableSchema({
  typeDefs,
  resolvers,
});

createApolloServer({
  schema,
});
