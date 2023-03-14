package models

import (
	"basic-auth-gin/types"
	"context"
	"errors"

	"basic-auth-gin/db"

	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

// UserSchema ...
type UserSchema struct {
	Id              primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Email           string             `bson:"email" json:"email" validate:"required"`
	Password        string             `bson:"password" json:"password,omitempty"`
	Name            string             `bson:"name" json:"name" validate:"required"`
	EmailConfirmed  bool               `bson:"emailConfirmed" json:"emailConfirmed,omitempty"`
	EmailToken      string             `bson:"emailToken" json:"emailToken,omitempty"`
	PermissionLevel int                `bson:"permissionLevel" json:"permissionLevel"`
	ExternalType    string             `bson:"externalType" json:"externalType"`
	ExternalId      string             `bson:"externalId" json:"externalId"`
}

// UserModel ...
type UserModel struct{}

var authModel = new(AuthModel)

var userCollection *mongo.Collection = db.GetCollection(db.DB, "users")

func (m UserModel) Update(filiter bson.M, data bson.M) (res *mongo.UpdateResult, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err = userCollection.UpdateMany(ctx, filiter, data)
	if err != nil {
		return res, err
	}
	return res, nil
}

// Login ...
func (m UserModel) Login(loginUser types.LoginType) (resUser types.User, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	emailFilter := bson.M{
		"email": loginUser.Email,
	}
	userInsertResult := userCollection.FindOne(ctx, emailFilter)
	var userWithDetail UserSchema
	err = userInsertResult.Decode(&userWithDetail)
	if err != nil {
		return resUser, err
	}
	err = userInsertResult.Decode(&resUser)
	if err != nil {
		return resUser, err
	}
	//Compare the password type and database if match
	bytePassword := []byte(loginUser.Password)
	byteHashedPassword := []byte(userWithDetail.Password)

	err = bcrypt.CompareHashAndPassword(byteHashedPassword, bytePassword)

	if err != nil {
		return resUser, err
	}
	return resUser, nil
}

// Register ...
func (m UserModel) Register(registerUser types.RegisterType) (resUser UserSchema, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	emailFilter := bson.M{
		"email": registerUser.Email,
	}
	var result bson.M
	//Check if the user exists in database
	err = userCollection.FindOne(ctx, emailFilter).Decode(&result)

	if err != nil {
		if err != mongo.ErrNoDocuments {
			return resUser, errors.New(err.Error())
		}
	} else {
		return resUser, errors.New("email already exists")
	}

	bytePassword := []byte(registerUser.Password)
	hashedPassword, err := bcrypt.GenerateFromPassword(bytePassword, bcrypt.DefaultCost)
	if err != nil {
		return resUser, errors.New("something went wrong, please try again later")
	}
	registerUser.Password = string(hashedPassword)
	var insertUser = &UserSchema{
		Id:              primitive.NewObjectID(),
		Email:           registerUser.Email,
		Password:        registerUser.Password,
		Name:            registerUser.Name,
		PermissionLevel: 0,
	}
	//Create the user and return back the user ID
	insertUserResult, err := userCollection.InsertOne(ctx, insertUser)
	if err != nil {
		return resUser, errors.New("something went wrong, please try again later")
	}
	resUser.Id = insertUserResult.InsertedID.(primitive.ObjectID)
	return resUser, err
}

func (m UserModel) EmailExist(email string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// check if a user with the given email exists in the Users collection
	filter := bson.M{"email": email}
	count, err := userCollection.CountDocuments(ctx, filter, nil)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func (m UserModel) InsertOrUpdateByEmail(email string, data interface{}) (user *UserSchema, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// check if a user with the given email exists in the Users collection
	filter := bson.M{"email": email}
	err = userCollection.FindOne(ctx, filter).Decode(&user)
	if err == mongo.ErrNoDocuments {
		// if the user doesn't exist, insert a new user with the given data
		_, err := userCollection.InsertOne(ctx, data)
		if err != nil {
			return user, err
		}
		return data.(*UserSchema), nil
	} else if err != nil {
		return user, err
	} else {
		// if the user exists, update the user with the given data
		//dataWithoutId, err := json.Marshal(data)
		if err != nil {
			return user, err
		}
		//var updateData types.UserNoId
		//json.Unmarshal([]byte(dataWithoutId), &updateData)
		// remove _id field from data to avoid error
		_, err = userCollection.UpdateOne(ctx, bson.M{"email": email}, bson.M{"$set": data}) //update by email
		if err != nil {
			return user, err
		}
		// return the updated user data
		err = userCollection.FindOne(ctx, filter).Decode(&user)
		if err != nil {
			return user, err
		}
		return user, nil
	}
}

// One ...
func (m UserModel) One(userID string) (user UserSchema, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	id, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return user, errors.New("userID parsing error")
	}
	res := userCollection.FindOne(ctx, bson.M{"_id": id})
	err = res.Decode(&user)
	if err != nil {
		return user, errors.New("user not found or format error")
	}
	return user, err
}
