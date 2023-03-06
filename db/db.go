package db

import (
	"basic-auth-gin/config"
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func ConnectDB() *mongo.Client {
	client, err := mongo.NewClient(options.Client().ApplyURI(config.Env.MONGOURI))
	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	//ping the database
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Connected to MongoDB")

	return client
}

// DB Client instance
var DB *mongo.Client = ConnectDB()

// GetCollection getting database collections
func GetCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	collection := client.Database("golangAPI").Collection(collectionName)

	return collection
}

// RedisClient Start Redis on database 1 - it's used to store the JWT, but you can use it for anything else
// Example: db.GetRedis().Set(KEY, VALUE, at.Sub(now)).Err()
// RedisClient ...
// var RedisClient *_redis.Client = InitRedis(1)

// func InitRedis(selectDB ...int) *_redis.Client {

// 	var redisHost = os.Getenv("REDIS_HOST")
// 	//var redisPassword = os.Getenv("REDIS_PASSWORD")

// 	_RedisClient := _redis.NewClient(&_redis.Options{
// 		Addr: redisHost,
// 		//Password: redisPassword,
// 		DB: selectDB[0],
// 		// DialTimeout:        10 * time.Second,
// 		// ReadTimeout:        30 * time.Second,
// 		// WriteTimeout:       30 * time.Second,
// 		// PoolSize:           10,
// 		// PoolTimeout:        30 * time.Second,
// 		// IdleTimeout:        500 * time.Millisecond,
// 		// IdleCheckFrequency: 500 * time.Millisecond,
// 		// TLSConfig: &tls.Config{
// 		// 	InsecureSkipVerify: true,
// 		// },
// 	})
// 	_, err := _RedisClient.Ping().Result()
// 	if err != nil {
// 		fmt.Println("redis connection error ", err)
// 	}
// 	//print("redis test: ", sta, "\n")
// 	return _RedisClient
// }

// // GetRedis ...
// func GetRedis() *_redis.Client {
// 	return RedisClient
// }
