//Deletes all comment history records from the program database, keeping only
//the current comments. Ghidra records every comment edit in a "Comment History"
//table (shown via right-click > Show History on a comment); mass comment
//imports bloat it. Run, then save the program.
//@category Comments
//@menupath Tools.Comments.Purge Comment History

import db.DBHandle;
import db.RecordIterator;
import db.Table;
import ghidra.app.script.GhidraScript;
import ghidra.program.database.ProgramDB;

public class PurgeCommentHistory extends GhidraScript {

	@Override
	public void run() throws Exception {
		DBHandle dbh = ((ProgramDB) currentProgram).getDBHandle();
		Table t = dbh.getTable("Comment History");
		if (t == null) {
			println("No 'Comment History' table in this program.");
			return;
		}
		int n = t.getRecordCount();
		RecordIterator it = t.iterator();
		while (it.hasNext()) {
			it.next();
			it.delete();
		}
		println("Deleted " + n + " comment history records (" + t.getRecordCount() + " left).");
	}
}
