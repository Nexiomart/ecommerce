const Mongoose = require('mongoose');

const { GROWTH_PARTNER_STATUS } = require('../constants');

const { Schema } = Mongoose;

// Growth Partner Schema
const GrowthPartnerSchema = new Schema({
  name: {
    type: String,
    trim: true
  },
  email: {
    type: String
  },
  phoneNumber: {
    type: String
  },
  brandName: {
    type: String
  },
  business: {
    type: String,
    trim: true
  },
  location: {
    type: String,
    trim: true
  },
  isActive: {
    type: Boolean,
    default: false
  },
  brand: {
    type: Schema.Types.ObjectId,
    ref: 'Brand',
    default: null
  },
  status: {
    type: String,
    default: GROWTH_PARTNER_STATUS.Waiting_Approval,
    enum: [
      GROWTH_PARTNER_STATUS.Waiting_Approval,
      GROWTH_PARTNER_STATUS.Rejected,
      GROWTH_PARTNER_STATUS.Approved
    ]
  },
  updated: Date,
  created: {
    type: Date,
    default: Date.now
  }
});

module.exports = Mongoose.model('GrowthPartner', GrowthPartnerSchema);
