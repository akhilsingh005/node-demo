import { MyContext } from "../types";
import { Resolver, InputType, Field, Mutation, Arg, Ctx, ObjectType, Query } from "type-graphql";
import { User } from "../entities/User";
import argon2 from "argon2";

@InputType()
class UsernamePasswordInput {
  @Field()
  username: string;
  @Field()
  password: string;
}

@ObjectType()
class FieldError {
  @Field()
  field: string;
  @Field()
  message: string;
}

@ObjectType()
class UserRespose {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[];
  @Field(() => User, { nullable: true })
  user?: User
}

@Resolver()
export class UserResolver {
@Query(() => User, { nullable: true })
  async me(@Ctx() { req, em }: MyContext) {
    // you are not logged in
    if(!req.session.userId) {
      return null;
    }

    const user = await em.findOne(User, { id: req.session.userId });
    return user;
  }


  @Mutation(() => UserRespose)
  async register(
    @Arg('options') options: UsernamePasswordInput,
    @Ctx() { em }: MyContext): Promise<UserRespose> {
      if(options.username.length <= 2) {
        return {
        errors: [
          {
            field: "username",
            message: "Username must be grater then 2"
          }
        ]
      }
    }
      if(options.password.length <= 3) {
        return {
        errors: [
          {
            field: "password",
            message: "password must be grater then 3"
          }
        ]
      }
    }
    const hassedPassword = await argon2.hash(options.password);
    const user = await em.create(User, { username: options.username, password: hassedPassword });
    try {
      await em.persistAndFlush(user);
    } catch (error) {
      // duplicate username error
      if(error.code === '23505') {
      return {
        errors: [
          {
            field: "username",
            message: "Username already taken."
          }
        ]
      }
    }
  }
    
    return { user };
  }

  @Mutation(() => UserRespose)
  async login(
    @Arg('options') options: UsernamePasswordInput,
    @Ctx() { em, req }: MyContext): Promise<UserRespose> {
    const user = await em.findOne(User, { username: options.username });
    if (!user) {
      return {
        errors: [{
          field: "username",
          message: "User dosen't exist."
        }]
      }
    }
    const valid = await argon2.verify(user.password, options.password);
    if (!valid) {
      return {
        errors: [{
          field: "password",
          message: "Password is incorrect."
        }]
      }
    }

    req.session['userId'] = user.id;

    return {
      user
    }
  }
}