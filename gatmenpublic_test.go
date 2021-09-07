package gatemanpublic

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/go-redis/redis/v8"
)

// Generates a new Redis client for Gateman tests
// TODO: figure out how to remove explicit Redis dependency, we could use a Store interface/abstraction
// with write and read methods
func NewRedis() *redis.Client {
	client := redis.NewClient(
		&redis.Options{
			Addr: "localhost:6379", Password: "",
			DB: 0,
		},
	)
	return client
}

func TestSeal(t *testing.T) {
	redisClient := NewRedis()
	gateman, err := NewGateman(
		"foo",
		redisClient, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	payload := GatemanPayload{
		Id:   "some-unique-id",
		Role: "user",
		Data: map[string]interface{}{
			"price":       "500",
			"product_id":  "12333",
			"order_state": "PROCESSING",
		},
	}

	token, err := gateman.Seal(payload, 0)

	if err != nil {
		t.Fatalf("Couldn't create token: %v", err)
	}

	if token == "" {
		t.Fatalf("Empty token generated")
	}
}

func TestUnseal(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	payload := GatemanPayload{
		Id:   "some-unique-id",
		Role: "user",
		Data: map[string]interface{}{
			"price":       "500",
			"product_id":  "111",
			"order_state": "WAITING",
		},
	}

	token, err := gateman.Seal(payload, 0)

	if err != nil {
		t.Fatalf("Couldn't generate token")
	}

	decodedPayload := GatemanPayload{}

	err = gateman.Unseal(token, &decodedPayload)

	if err != nil {
		t.Fatalf("Couldn't unseal token: %v", err)
	}

	if !reflect.DeepEqual(decodedPayload, payload) {
		t.Fatalf("Could not unseal token")
	}
}

func TestCreateSession(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	id := "some-unique-id"
	role := "user"

	token, err := gateman.CreateSession(id, role, nil)

	if err != nil {
		t.Fatalf("Could not create session: %v", err)
	}

	if token == "" {
		t.Fatalf("Empty token generated")
	}

	// validate that the token exists in Redis (store)
	// we internally use the `id` as the key in Redis (store)
	retrievedToken, _ := gateman.redis.Get(context.TODO(), id).Result()

	if retrievedToken == "" {
		t.Fatalf("Token was not persisted in Redis")
	}

	if retrievedToken != token {
		t.Fatalf("Invalid token found in Redis for provided id")
	}
}

func TestCreateHeadlessToken(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	id := "some-unique-id-12"

	token, err := gateman.CreateHeadlessToken(id, nil)

	if err != nil {
		t.Fatalf("Could not create session: %v", err)
	}

	if token == "" {
		t.Fatalf("Empty token generated")
	}

	// TODO: Validate headless token TTL
}

func TestGuardWithNoAuthHeader(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	// testHandler is the request handler which `guard` calls
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Guard worked"))
	}

	handler := http.HandlerFunc(testHandler)

	// wrap the handler with a user guard
	handlerWithGuard := gateman.Guard([]string{"user"}, nil)(handler)

	// Create a test request object without headers specified
	req, err := http.NewRequest("POST", "/auth", nil)

	if err != nil {
		t.Error(err)
	}

	rr := httptest.NewRecorder()

	handlerWithGuard.ServeHTTP(rr, req)

	// Todo: We could use error constants to validate that the right error message is returndd
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("guard should fail if no authorization header is found")
	}
}

// Benchmarks

func BenchmarkSeal(b *testing.B) {
	payload := GatemanPayload{
		Id:   "123",
		Role: "user",
	}

	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		b.Fatalf("Couldn't initialize gateman: %v", err)
	}

	for i := 0; i < b.N; i++ {
		gateman.Seal(payload, 0)
	}
}

func BenchmarkUnSeal(b *testing.B) {
	payload := GatemanPayload{
		Id:   "123",
		Role: "user",
	}

	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		b.Fatalf("Couldn't initialize gateman: %v", err)
	}

	token, err := gateman.Seal(payload, 0)

	if err != nil {
		b.Fatalf("Couldn't generate token: %v", err)
	}

	for i := 0; i < b.N; i++ {
		result := &GatemanPayload{}
		gateman.Unseal(token, result)
	}
}

func TestGuardWithAuthHeader(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	// testHandler is the request handler which `guard` calls
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Guard worked"))
	}

	id := "123"
	role := "user"

	token, err := gateman.CreateSession(id, role, nil)

	if err != nil {
		t.Fatalf("Could not create session: %v", err)
	}

	handler := http.HandlerFunc(testHandler)
	newToken := fmt.Sprintf("Bearer %s", token)

	handlerWithGuard := gateman.Guard([]string{"user"}, nil)(handler)
	// Create a test request object  headers specified
	req, err := http.NewRequest("POST", "/auth", nil)
	req.Header.Set("Authorization", newToken)
	if err != nil {
		t.Error(err)
	}

	rr := httptest.NewRecorder()

	handlerWithGuard.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("guard should fail if no authorization header is found")
	}

}

func TestHeadlessToken(t *testing.T) {
	redis := NewRedis()

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	// testHandler is the request handler which `guard` calls
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Guard worked"))
	}

	id := "123"

	token, _ := gateman.CreateHeadlessToken(id, nil)

	handler := http.HandlerFunc(testHandler)
	newToken := fmt.Sprintf("foo-serivce %s", token)

	handlerWithGuard := gateman.Guard(nil, []string{"foo"})(handler)
	// Create a test request object  headers specified
	req, err := http.NewRequest("POST", "/auth", nil)
	req.Header.Set("Authorization", newToken)
	if err != nil {
		t.Error(err)
	}

	rr := httptest.NewRecorder()

	handlerWithGuard.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("guard should fail if no authorization header is found")
	}

}

func TestServices(t *testing.T) {
	redis := NewRedis()
	id := "1234"

	gateman, err := NewGateman(
		"foo",
		redis, "foo-serivce",
		"4f3f6638d609c7a7df74b317290763dc18c66a72eb35fbdd04f6c114fd558060",
		0,
	)

	if err != nil {
		t.Fatalf("Couldn't initialize gateman: %v", err)
	}

	// testHandler is the request handler which `guard` calls
	testHandler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Guard worked"))
	}

	token, err := gateman.CreateHeadlessToken(id, nil)
	if err != nil {
		t.Fatalf("Couldn't create token: %v", err)
	}

	handler := http.HandlerFunc(testHandler)
	newToken := fmt.Sprintf("foo-serivce %s", token)
	handlerWithGuard := gateman.Guard([]string{"service"}, []string{"foo"})(handler)
	// Create a test request object  headers specified
	req, err := http.NewRequest("POST", "/auth", nil)
	req.Header.Set("Authorization", newToken)
	if err != nil {
		t.Error(err)
	}

	rr := httptest.NewRecorder()

	handlerWithGuard.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("guard should fail if no authorization header is found")
	}

}
