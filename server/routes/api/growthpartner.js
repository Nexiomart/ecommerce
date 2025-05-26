const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Bring in Models & Helpers
const { GROWTH_PARTNER_STATUS, ROLES } = require('../../constants');
const GrowthPartner = require('../../models/growthpartner');
const User = require('../../models/user');
const Brand = require('../../models/brand');
const auth = require('../../middleware/auth');
const role = require('../../middleware/role');
const mailgun = require('../../services/mailgun');

// Add Growth Partner API
router.post('/add', async (req, res) => {
  try {
    const { name, business, phoneNumber, email, brandName, location } = req.body;

    if (!name || !email) {
      return res.status(400).json({ error: 'You must enter your name and email.' });
    }

    if (!business) {
      return res.status(400).json({ error: 'You must enter a business description.' });
    }

    if (!phoneNumber || !email) {
      return res.status(400).json({ error: 'You must enter a phone number and an email address.' });
    }

    const existingPartner = await GrowthPartner.findOne({ email });

    if (existingPartner) {
      return res.status(400).json({ error: 'That email address is already in use.' });
    }

    const partner = new GrowthPartner({
      name,
      email,
      business,
      phoneNumber,
      brandName,
      location
    });
    const partnerDoc = await partner.save();

    await mailgun.sendEmail(email, 'growth-partner-application');

    res.status(200).json({
      success: true,
      message: `We received your request! We will reach you on your phone number ${phoneNumber}!`,
      growthPartner: partnerDoc
    });
  } catch (error) {
    return res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Search Growth Partners
router.get('/search', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const { search } = req.query;
    const regex = new RegExp(search, 'i');

    const partners = await GrowthPartner.find({
      $or: [
        { phoneNumber: { $regex: regex } },
        { email: { $regex: regex } },
        { name: { $regex: regex } },
        { brandName: { $regex: regex } },
        { status: { $regex: regex } }
      ]
    }).populate('brand', 'name');

    res.status(200).json({ partners });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Fetch all Growth Partners
router.get('/', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;

    const partners = await GrowthPartner.find()
      .populate('brand')
      .sort('-created')
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .exec();

    const count = await GrowthPartner.countDocuments();

    res.status(200).json({
      partners,
      totalPages: Math.ceil(count / limit),
      currentPage: Number(page),
      count
    });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Disable Growth Partner
router.put('/:id/active', auth, async (req, res) => {
  try {
    const partnerId = req.params.id;
    const update = req.body.partner;
    const query = { _id: partnerId };

    const partnerDoc = await GrowthPartner.findOneAndUpdate(query, update, {
      new: true
    });

    if (!update.isActive) {
      await deactivateBrand(partnerId);
      await mailgun.sendEmail(partnerDoc.email, 'growth-partner-deactivate-account');
    }

    res.status(200).json({ success: true });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Approve Growth Partner
router.put('/approve/:id', auth, async (req, res) => {
  try {
    const partnerId = req.params.id;
    const query = { _id: partnerId };
    const update = {
      status: GROWTH_PARTNER_STATUS.Approved,
      isActive: true
    };

    const partnerDoc = await GrowthPartner.findOneAndUpdate(query, update, {
      new: true
    });

    await createPartnerUser(
      partnerDoc.email,
      partnerDoc.name,
      partnerId,
      req.headers.host
    );

    res.status(200).json({ success: true });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Reject Growth Partner
router.put('/reject/:id', auth, async (req, res) => {
  try {
    const partnerId = req.params.id;

    const query = { _id: partnerId };
    const update = { status: GROWTH_PARTNER_STATUS.Rejected };

    await GrowthPartner.findOneAndUpdate(query, update, {
      new: true
    });

    res.status(200).json({ success: true });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Signup Partner with token
router.post('/signup/:token', async (req, res) => {
  try {
    const { email, firstName, lastName, password } = req.body;

    if (!email || !firstName || !lastName || !password) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const userDoc = await User.findOne({
      email,
      resetPasswordToken: req.params.token
    });

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(password, salt);

    const query = { _id: userDoc._id };
    const update = {
      email,
      firstName,
      lastName,
      password: hash,
      resetPasswordToken: undefined
    };

    await User.findOneAndUpdate(query, update, { new: true });

    const partnerDoc = await GrowthPartner.findOne({ email });
    await createPartnerBrand(partnerDoc);

    res.status(200).json({ success: true });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Delete Growth Partner
router.delete('/delete/:id', auth, role.check(ROLES.Admin), async (req, res) => {
  try {
    const partnerId = req.params.id;
    await deactivateBrand(partnerId);
    const partner = await GrowthPartner.deleteOne({ _id: partnerId });

    res.status(200).json({
      success: true,
      message: `Growth Partner has been deleted successfully!`,
      partner
    });
  } catch (error) {
    res.status(400).json({
      error: 'Your request could not be processed. Please try again.'
    });
  }
});

// Helper Functions
const deactivateBrand = async partnerId => {
  const partnerDoc = await GrowthPartner.findOne({ _id: partnerId }).populate('brand', '_id');
  if (!partnerDoc || !partnerDoc.brand) return;
  const brandId = partnerDoc.brand._id;
  const update = { isActive: false };
  return await Brand.findOneAndUpdate({ _id: brandId }, update, { new: true });
};

const createPartnerBrand = async ({ _id, brandName, business }) => {
  const newBrand = new Brand({
    name: brandName,
    description: business,
    growthPartner: _id,
    isActive: false
  });

  const brandDoc = await newBrand.save();

  await GrowthPartner.findOneAndUpdate({ _id }, { brand: brandDoc._id });
};

const createPartnerUser = async (email, name, partner, host) => {
  const firstName = name;
  const lastName = '';

  const existingUser = await User.findOne({ email });

  if (existingUser) {
    const update = { growthPartner: partner, role: ROLES.GrowthPartner };

    const partnerDoc = await GrowthPartner.findOne({ email });
    await createPartnerBrand(partnerDoc);
    await mailgun.sendEmail(email, 'growth-partner-welcome', null, name);

    return await User.findOneAndUpdate({ _id: existingUser._id }, update, { new: true });
  } else {
    const buffer = await crypto.randomBytes(48);
    const resetPasswordToken = buffer.toString('hex');

    const user = new User({
      email,
      firstName,
      lastName,
      resetPasswordToken,
      growthPartner: partner,
      role: ROLES.GrowthPartner
    });

    await mailgun.sendEmail(email, 'growth-partner-signup', host, {
      resetToken: resetPasswordToken,
      email
    });

    return await user.save();
  }
};

module.exports = router;
