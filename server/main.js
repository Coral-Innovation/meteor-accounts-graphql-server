import { createApolloServer } from "meteor/apollo";
import { Random } from "meteor/random";

import { GraphQLDateTime } from "graphql-iso-date";
import { makeExecutableSchema } from "graphql-tools";

const typeDefs = `
  scalar Date

  type LoginResponse {
    userId: ID!
    loginToken: String!
    loginTokenExpires: Date!
  }

  type Mutation {
    loginWithPassword(email: String!, password: String!): LoginResponse
    logout(userId: String!, loginToken: String!): Boolean
  }

  type Query {
    ping: String
  }
`;

// Inspiration for resolvers: 
// https://github.com/davidyaha/apollo-accounts-server/blob/master/server/imports/models/user-account.js
// https://github.com/stubailo/meteor-rest/blob/devel/packages/rest-accounts-password/rest-login.js

const resolvers = {
  Date: GraphQLDateTime,
  Mutation: {
    loginWithPassword: (obj, args, context) => {
      return new Promise((resolve, reject) => {
        const user = Accounts.findUserByEmail(args.email);
        if (!user) {
          reject(new Error("Couldn't find user."));
        }
        
        const { userId, error } = Accounts._checkPassword(user, args.password);
        if (error) {
          reject(error);
        }
        
        const token = Random.secret();
        const when = new Date();
        Accounts._insertLoginToken(user._id, { token, when });

        // Return according to LocalStorage keys "Meteor.userId", "Meteor.loginToken", "Meteor.loginTokenExpires"
        resolve({
          userId: user._id,
          loginToken: token,
          loginTokenExpires: Accounts._tokenExpiration(when)
        });
      });
    },
    // Meteor accounts-base retrieves the loginToken from the current LiveData connection.
    // Since we don't use this, we need to provide the loginToken as an argument.
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
