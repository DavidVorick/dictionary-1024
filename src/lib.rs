#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(unused_must_use)]
#![deny(unused_mut)]

//! dictionary-1024 is a mnemonic dictionary that can be used with cryptographic seeds or to
//! transform other binary data. The dictionary has 1024 words in it, which means you can pack
//! exactly 10 bits of entropy into each word. The dictionary has the property that every word can
//! be uniquely determined by its first 3 characters. The API is designed such that only the first
//! 3 characters of a word are considered when doing a lookup in the dictionary.
//!
//! This is a helper library that is used in downstream crates such as seed15 and mnemonic-16bit.
//!
//! ```
//! let word = dictionary_1024::word_at_index(5); // "ace"
//! let index = dictionary_1024::index_of_word(&word); // 5
//! ```

/// DICTIONARY_UNIQUE_PREFIX defines the number of characters that are guaranteed to be unique for
/// each word in the dictionary. The seed code only looks at these three characters when parsing a
/// word, allowing users to make substitutions for words if they prefer or find it easier to
/// memorize.
///
/// This constant is here for documentation purposes.
pub const DICTIONARY_UNIQUE_PREFIX: usize = 3;

/// DICTIONARY contains the dictionary-1024 wordlist. This const is here for documentation
/// purposes. Use the methods for accessing the dictionary instead.
pub const DICTIONARY: [&str; 1024] = [
    "abbey", "able", "abort", "absorb", "abyss", "ace", "ache", "acid", "across", "acumen",
    "adapt", "adept", "adjust", "adopt", "adult", "aerial", "afar", "affair", "afield", "afloat",
    "afoot", "afraid", "after", "age", "agile", "aglow", "agony", "agree", "ahead", "aid", "aisle",
    "ajar", "akin", "alarm", "album", "alert", "alley", "almost", "aloof", "alps", "also",
    "alumni", "always", "amaze", "ambush", "amidst", "ammo", "among", "ample", "amuse", "anchor",
    "angle", "ankle", "antic", "anvil", "apart", "apex", "aphid", "aplomb", "apply", "arch",
    "ardent", "arena", "argue", "arise", "arm", "around", "arrow", "ascend", "aside", "ask",
    "asleep", "aspire", "asylum", "atlas", "atom", "atrium", "attire", "auburn", "audio", "august",
    "aunt", "auto", "avatar", "avid", "avoid", "awful", "awning", "awoken", "axe", "axis", "axle",
    "aztec", "azure", "baby", "bacon", "bad", "bail", "bakery", "bamboo", "banjo", "basin",
    "batch", "bawl", "bay", "beer", "befit", "begun", "behind", "being", "below", "best", "bevel",
    "beware", "beyond", "bias", "bid", "bike", "bird", "bite", "blip", "boat", "body", "bogey",
    "boil", "bold", "bomb", "border", "boss", "both", "bovine", "box", "broken", "brunt", "bubble",
    "budget", "buffet", "bug", "bulb", "bum", "bun", "but", "buy", "buzz", "byline", "bypass",
    "cabin", "cactus", "cadet", "cafe", "cage", "cajun", "cake", "camp", "candy", "case", "cat",
    "cause", "cease", "cedar", "cell", "cement", "cent", "chrome", "cider", "cigar", "cinema",
    "circle", "claw", "click", "clue", "coal", "cobra", "cocoa", "code", "coffee", "cog", "coil",
    "cold", "comb", "cool", "copy", "cousin", "cowl", "cube", "cuff", "custom", "dad", "daft",
    "dagger", "daily", "dam", "dapper", "dart", "dash", "date", "dawn", "daze", "debt", "decay",
    "deft", "deity", "den", "depth", "desk", "devoid", "dice", "diet", "dig", "dilute", "dim",
    "dine", "diode", "ditch", "dive", "dizzy", "doctor", "dodge", "doe", "dog", "doing", "donut",
    "dose", "dot", "double", "dove", "down", "doze", "dream", "drink", "drunk", "dry", "dual",
    "dubbed", "dud", "duet", "duke", "dumb", "dune", "duplex", "dust", "duty", "dwarf", "dwelt",
    "dying", "each", "eagle", "earth", "easy", "eat", "echo", "eden", "edgy", "edit", "eel", "egg",
    "eight", "either", "eject", "elapse", "elbow", "eldest", "eleven", "elite", "elope", "else",
    "elude", "email", "ember", "emerge", "emit", "empty", "energy", "enigma", "enjoy", "enlist",
    "enmity", "enough", "ensign", "envy", "epoxy", "equip", "erase", "error", "estate", "etch",
    "ethics", "excess", "exhale", "exit", "exotic", "extra", "exult", "fade", "fake", "fall",
    "family", "fancy", "fatal", "fault", "fawn", "fax", "faze", "feast", "fee", "felt", "fence",
    "ferry", "fever", "few", "fiat", "fibula", "fidget", "fierce", "fight", "film", "fir", "five",
    "fix", "fizz", "fleet", "fly", "foam", "focus", "foe", "fog", "foil", "font", "fossil", "fowl",
    "fox", "foyer", "frame", "frown", "fruit", "fry", "fudge", "fuel", "full", "fume", "fun",
    "future", "fuzz", "gables", "gadget", "gag", "gain", "galaxy", "game", "gang", "gasp",
    "gather", "gauze", "gave", "gawk", "gaze", "gecko", "geek", "gel", "germ", "geyser", "ghetto",
    "ghost", "giant", "giddy", "gift", "gill", "ginger", "girth", "give", "glass", "glide", "gnaw",
    "gnome", "goat", "goblet", "goes", "going", "gone", "gopher", "gossip", "got", "gown", "grunt",
    "guest", "guide", "gulp", "guru", "gust", "gutter", "guy", "gypsy", "gyrate", "hair", "having",
    "hawk", "haze", "heel", "heft", "height", "hence", "hero", "hide", "hijack", "hike", "hill",
    "hinder", "hip", "hire", "hive", "hoax", "hobby", "hockey", "hold", "honk", "hook", "hop",
    "horn", "hot", "hover", "howl", "huddle", "hug", "hull", "hum", "hunt", "hut", "hybrid",
    "hyper", "icing", "icon", "idiom", "idle", "idol", "igloo", "ignore", "iguana", "impel",
    "incur", "injury", "inline", "inmate", "input", "insult", "invoke", "ion", "irate", "iris",
    "iron", "island", "issue", "itch", "item", "itself", "ivory", "jab", "jade", "jagged", "jail",
    "jargon", "jaunt", "jaw", "jazz", "jeans", "jeer", "jest", "jewel", "jigsaw", "jingle", "jive",
    "job", "jock", "jog", "joke", "jolt", "jostle", "joy", "judge", "juicy", "july", "jump",
    "junk", "jury", "karate", "keep", "kennel", "kept", "kettle", "king", "kiosk", "kiss", "kiwi",
    "knee", "knife", "koala", "lad", "lag", "lair", "lake", "lamb", "lap", "large", "last",
    "late", "lava", "lay", "lazy", "ledge", "leech", "left", "legion", "lemon", "lesson", "liar",
    "lick", "lid", "lie", "light", "lilac", "lime", "line", "lion", "liquid", "list", "live",
    "load", "lock", "lodge", "loft", "logic", "long", "lopped", "lost", "loud", "love", "low",
    "loyal", "lucky", "lump", "lung", "lurk", "lush", "luxury", "lymph", "lynx", "lyrics", "macro",
    "mail", "major", "make", "male", "mammal", "map", "mate", "maul", "mayor", "maze", "mean",
    "memoir", "men", "merge", "mesh", "met", "mew", "mice", "midst", "mighty", "mime", "mirror",
    "misery", "moat", "mob", "mock", "mohawk", "molten", "moment", "money", "moon", "mop",
    "morsel", "most", "mouth", "mow", "much", "mud", "muffin", "mug", "mullet", "mumble", "muppet",
    "mural", "muzzle", "myriad", "myth", "nag", "nail", "name", "nanny", "nap", "nasty", "navy",
    "near", "need", "neon", "nephew", "nerve", "nest", "never", "newt", "nexus", "nibs", "niche",
    "niece", "nifty", "nimbly", "nobody", "nod", "noise", "nomad", "note", "noun", "nozzle",
    "nuance", "nudged", "nugget", "null", "numb", "nun", "nurse", "nylon", "oak", "oar", "oasis",
    "object", "occur", "ocean", "odd", "off", "often", "okay", "older", "olive", "omega", "onion",
    "online", "onto", "onward", "ooze", "open", "opus", "orange", "orb", "orchid", "order",
    "organ", "origin", "oscar", "otter", "ouch", "ought", "ounce", "oust", "oval", "oven", "owe",
    "owl", "own", "oxygen", "oyster", "ozone", "pact", "page", "palace", "paper", "past", "pat",
    "pause", "peel", "peg", "pen", "people", "pepper", "pest", "petal", "phase", "phone", "piano",
    "pick", "pierce", "pimple", "pirate", "pivot", "pixel", "pizza", "plead", "pliers", "plus",
    "poetry", "point", "poke", "pole", "pony", "pool", "pot", "pouch", "powder", "pray", "pride",
    "prune", "pry", "public", "puck", "puddle", "puff", "pulp", "punch", "puppy", "purge", "push",
    "putty", "pylon", "python", "queen", "quick", "quote", "radar", "raft", "rage", "rake",
    "rally", "ram", "rapid", "rare", "rash", "rat", "rave", "ray", "razor", "react", "rebel",
    "recipe", "reduce", "reef", "refer", "reheat", "relic", "remedy", "repent", "rerun", "rest",
    "return", "revamp", "rewind", "rhino", "rhyme", "rib", "rich", "ride", "rift", "rigid", "rim",
    "riot", "rip", "rise", "ritual", "river", "roar", "robot", "rodent", "rogue", "role", "room",
    "rope", "roster", "rotate", "rover", "royal", "ruby", "rude", "rug", "ruin", "rule", "rumble",
    "run", "rural", "sack", "safe", "saga", "sail", "sake", "salad", "sample", "sand", "sash",
    "satin", "save", "scenic", "school", "scoop", "scrub", "scuba", "second", "sedan", "seed",
    "setup", "sew", "sieve", "silk", "sip", "siren", "size", "skate", "skew", "skull", "slid",
    "slow", "slug", "smash", "smog", "snake", "sneeze", "sniff", "snout", "snug", "soap", "sob",
    "soccer", "soda", "soggy", "soil", "solve", "sonar", "soot", "sort", "sow", "soy", "space",
    "speed", "sphere", "spout", "sprig", "spud", "spy", "square", "stick", "subtly", "suede",
    "sugar", "sum", "sun", "surf", "sushi", "suture", "swept", "sword", "swung", "system", "tab",
    "tacit", "tag", "taint", "take", "talent", "tamper", "tan", "task", "tattoo", "taunt",
    "tavern", "tawny", "taxi", "tell", "tender", "tepid", "tether", "thaw", "thorn", "thumb",
    "thwart", "ticket", "tidy", "tier", "tiger", "tilt", "timber", "tint", "tip", "tire", "tissue",
    "titan", "today", "toffee", "toilet", "token", "tone", "top", "torn", "toss", "total", "touch",
    "tow", "toxic", "toy", "trash", "trend", "tribal", "truth", "try", "tube", "tuck", "tudor",
    "tuft", "tug", "tulip", "tune", "turn", "tusk", "tutor", "tuxedo", "twang", "twice", "tycoon",
    "type", "tyrant", "ugly", "ulcer", "umpire", "uncle", "under", "uneven", "unfit", "union",
    "unmask", "unrest", "unsafe", "until", "unveil", "unwind", "unzip", "upbeat", "update",
    "uphill", "upkeep", "upload", "upon", "upper", "urban", "urge", "usage", "use", "usher",
    "using", "usual", "utmost", "utopia", "vague", "vain", "value", "vane", "vary", "vat", "vault",
    "vector", "veer", "vegan", "vein", "velvet", "vest", "vexed", "vial", "vice", "video",
    "viking", "violin", "viper", "vital", "vivid", "vixen", "vocal", "vogue", "voice", "vortex",
    "vote", "vowel", "voyage", "wade", "waffle", "waist", "wake", "want", "warp", "water", "wax",
    "wedge", "weird", "went", "wept", "were", "whale", "when", "whole", "wide", "wield", "wife",
    "wiggle", "wild", "winter", "wire", "wise", "wives", "wizard", "wobbly", "woes", "woke",
    "wolf", "woozy", "worry", "woven", "wrap", "wrist", "wrong", "yacht", "yahoo", "yank",
];

/// word_at_index will return the word with the provided index. If the index is greater than 1023,
/// the program will panic.
pub fn word_at_index(i: usize) -> String {
    if i > 1023 {
        panic!("attempt to access index {} but dictionary-1024 only has 1024 elements", i);
    }
    DICTIONARY[i].to_string()
}

/// index_of_word will return the index of the provided word within the dictionary, using only the
/// first three characters of the word to find a match. If no match is found, an error will be
/// returned.
pub fn index_of_word(word: &str) -> Result<usize, String> {
    if word.len() < 3 {
        return Err("each word must have at least three characters".to_string());
    }
    let word = &word[..3];

    for i in 0..1024 {
        if &DICTIONARY[i][..3] == word {
            return Ok(i);
        }
    }
    return Err("word was not found in the dictionary".to_string());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_tests() {
        // Try all words without making changes.
        for i in 0..1024 {
            let word = word_at_index(i);
            let index = index_of_word(&word).unwrap();
            if index != i {
                panic!("mismatch");
            }
        }

        // Try all words while adding extensions.
        for i in 0..1024 {
            let mut word = word_at_index(i);
            word += "b";
            let index = index_of_word(&word).unwrap();
            if index != i {
                panic!("mismatch");
            }
        }

        // Try all words while modifying the 4th character if it exists.
        for i in 0..1024 {
            let mut word = word_at_index(i);
            word.truncate(3);
            word += "a";
            let index = index_of_word(&word).unwrap();
            if index != i {
                panic!("mismatch");
            }
        }

        // Try all words truncated to just three characters.
        for i in 0..1024 {
            let mut word = word_at_index(i);
            word.truncate(3);
            let index = index_of_word(&word).unwrap();
            if index != i {
                panic!("mismatch");
            }
        }

        // Check for errors.
        index_of_word("aaron").unwrap_err();
        index_of_word("ab").unwrap_err();
    }
}
