import Severity from "./Severity.js";
import MessageCatalog from "./MessageCatalog.js";

export default class Message{

    constructor({ text = null, code = null, severity = null, data = null }) {

        const catalog = code ? MessageCatalog.map[code] : null;

        this.code = code || null;
        this.title = catalog?.title || text || "Unknown Issue";

        // we use data for additional informations
        this.details = catalog?.details || "";
        if (data) {
            this.details = this.details ? `${this.details} (${data})` : data;
        }

        this.category = catalog?.category || "custom";

        this.severity =
            severity ||
            catalog?.severity ||
            Severity.INFO;
    }
}