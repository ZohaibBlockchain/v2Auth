// models/user.js
import {mongoose} from'mongoose';


const userSchema = new mongoose.Schema({
  email: {unique:true,type: String},
  password: String,
  accountStatus:Boolean,
});

export default mongoose.model('User', userSchema);

