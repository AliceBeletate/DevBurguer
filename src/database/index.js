import Sequelize from "sequelize";
import mongoose from 'mongoose';

import configDatabase from "../config/database";

import User from "../app/models/users";
import Product from "../app/models/products";
import Category from "../app/models/category";

const models = [User, Product, Category];

class Database {
    constructor() {
        this.init();
        this.mongo();
    }

    init() {
        this.connection = new Sequelize(configDatabase)
        models.map((model) => model.init(this.connection)).map(model => model.associate && model.associate(this.connection.models), );
    }
    mongo(){
        this.mongoConnection = mongoose.connect('mongodb://localhost:27017/devburger',);
    }
}
export default new Database();