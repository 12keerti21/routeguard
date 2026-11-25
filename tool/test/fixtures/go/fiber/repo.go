package main

import "go.mongodb.org/mongo-driver/mongo"

type invoiceRepo struct{ col *mongo.Collection }

var repo = &invoiceRepo{}

func (r *invoiceRepo) GetInvoice(id string) (map[string]any, error) {
	var out map[string]any
	err := r.col.FindOne(nil, map[string]any{"_id": id}).Decode(&out)
	return out, err
}
