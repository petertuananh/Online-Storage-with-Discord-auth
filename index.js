const config = require("./config/config.json")
var express = require('express');
const url = require("url");
var app = express();
var path = require('path');
var server = require('http').createServer(app);
const fs = require("fs")
const multer = require('multer');
const session = require("express-session");
const passport = require("passport");
const MemoryStore = require("memorystore")(session);
const Strategy = require("passport-discord").Strategy;
const { QuickDB } = require("quick.db");
const db = new QuickDB();
const domain = config.server.domain || `http://localhost:${config.server.port}`
app.use(require('cookie-parser')());
var bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({
   extended: false
}));
app.use(bodyParser.json()); 
server.listen(config.server.port, function() {
    console.log('Server listening at port %d', config.server.port);
});
app.set('view engine', 'ejs');
app.use(express.static(path.join(__dirname, 'public')));
const dataDir = path.resolve(`${process.cwd()}${path.sep}views`);
app.use("/", express.static(path.resolve(`${dataDir}${path.sep}assets`)))
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));
passport.use(
    new Strategy(
        {
            clientID: config.discord.id,
            clientSecret: config.discord.secret,
            callbackURL: `${domain}/callback`,
            scope: ["identify", "guilds"],
        },
        (accessToken, refreshToken, profile, done) => {
            process.nextTick(() => done(null, profile));
        },
    ),
);
app.use(
    session({
        store: new MemoryStore({ checkPeriod: 86400000 }),
        secret:
			"#@%#&^$^$%@$^$&%#$%@#$%$^%&$%^#$%@#$%#E%#%@$FEErfgr3g#%GT%536c53cc6%5%tv%4y4hrgrggrgrgf4n",
        resave: false,
        saveUninitialized: false,
    }),
);


app.use(passport.initialize());
app.use(passport.session());
app.use(
    bodyParser.urlencoded({
      extended: true,
    }),
);

const checkAuth = async (req, res, next) => {
    if (req.isAuthenticated()) return next();
    req.session.backURL = req.url;
    res.redirect("/login");
};

app.get("/", async(req, res) => {
    res.redirect("/home");
})


app.get("/signup/secret", checkAuth, async(req, res) => {
    const userId = req.user.id
    const nowUser = await db.get(`user_${userId}`)
    if (nowUser) {
        res.redirect(`/${userId}/view`)
    } else {
        await db.set(`user_${userId}`, userId)
        var dir = `./data/${userId}`;
        if (!fs.existsSync(dir)){
            await fs.mkdirSync(dir, { recursive: true });
        }
        return res.redirect(`/${userId}/view`)
    }
})

app.get("/login", async(req, res, next) => {
    if (req.session.backURL) {
        req.session.backURL = req.session.backURL;
    } else if (req.headers.referer) {
        const parsed = url.parse(req.headers.referer);
        if (parsed.hostname === app.locals.domain) {
          req.session.backURL = parsed.path;
        }
    } else {
        req.session.backURL = "/";
    }
    next();
},passport.authenticate("discord"))

app.get('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
  });
app.get("/callback", passport.authenticate("discord", { failureRedirect: "/" }),(req,res) => {
    if (req.session.backURL) {
        const backURL = req.session.backURL;
        req.session.backURL = null;
        res.redirect(backURL);
    } else {
        res.redirect("/");
    }
})

app.get("/home", async(req, res) => {
    res.render('pages/home', {
        user: req.user
    });
})
app.get("/:id/:action", async(req, res) => {
    let loggedin
    let user
    if (!req.user) {
        loggedin = false
        user = req.params.id
        if (await db.get(`public_${user}`) !== 'checked') return sendError(req, res, `You don't have permission to view`, `${domain}/home`)
    } else {
        loggedin = req.user.id
        user = req.user.id
        if (req.params.id !== req.user.id && await db.get(`public_${user}`) !== true) return sendError(req, res, `You don't have permission to view`, `${domain}/home`)
    }
    let userData
    try {
        userData = fs.readdirSync(`./data/${user}`)
    } catch (error) {
        return sendError(req, res, `You didn't signup before`, `${domain}/home`)
    }
    const dataDir = path.resolve(`${process.cwd()}${path.sep}data${path.sep}${user}`);
    const action = req.params.action
    const file = req.query.file
    if (action == 'view') {
        if (file) {
            let blacklisted = [
                ".png", ".gif", ".jpg", ".jpeg", ".mp3", ".mp4"
            ]
            let foundInText = false;
            for (var i in blacklisted) {
                if (file.toLowerCase().includes(blacklisted[i].toLowerCase())) foundInText = true;
            }

            if (foundInText) {
                res.sendFile(`${dataDir}/${file}`, function (err) {
                    if (err) {
                        sendError(req, res, `Can't find your file`, `${domain}/${user}/view`)
                    }
                })
            } else {
                res.download(`${dataDir}/${file}`, file, function (err) {
                    if (err) {
                        sendError(req, res, `Can't find your file`, `${domain}/${user}/view`)
                    }
                })
            }
        } else {
            res.render('pages/view', {
                public : await db.get(`public_${user}`),
                loggedin : loggedin,
                user: req.user,
                nowURL: req.url,
                deleteURL: `${domain}/${user}/delete`,
                files: userData
            });
        }
    } else if (action == 'delete') {
        if (!req.user) {
            return
        } else if (req.user.id == req.params.id) {
            try {
                fs.unlinkSync(`${dataDir}/${file}`, function(err){
                    if (err) {
                        sendError(req, res, `Can't find your file`, `${domain}/${user}/view`)
                    }
                })
                return sendSucess(req, res, `Deleted!`, `${domain}/${user}/view`) 
            } catch (error) {
                return sendError(req, res, `Can't find your file`, `${domain}/${user}/view`)
            }
        }
    }
})

app.post("/:id/:action", checkAuth, async(req, res) => {
    const user = await req.user
    if (req.body.btn) {
        await db.set(`public_${user.id}`, `checked`)
        console.log(await db.get(`public_${user.id}`))


        return res.redirect(`${domain}/${user.id}/view`)
    } else {
        let storage = multer.diskStorage({
            destination: function (req, file, callback) {
                callback(null, `./data/${user.id}`)
            },
            filename: function (req, file, callback) {
                callback(null, file.originalname)
            }
        })
        let upload = multer({
            storage: storage,
            fileFilter: function (req, file, callback) {
                let ext = path.extname(file.originalname)
                callback(null, true)
            }
        }).array('userFile', 99999999);
        upload(req, res, function (err) {
            return sendSucess(req, res, `Uploaded!`, `${domain}/${user.id}/view`)
        })
    }
})

async function sendError(req, res, error, backURL) {
    res.render('pages/error', {
        error: error,
        backURL: backURL
    });
}
async function sendSucess(req, res, success, backURL) {
    res.render('pages/success', {
        success: success,
        backURL: backURL
    });
}