-- A failed check no longer closes the intake: it waits for the administrator like the others,
-- and can be re-checked.
DROP TRIGGER intakes_1_status ON mint.intakes;
CREATE TRIGGER intakes_1_status BEFORE INSERT OR UPDATE ON mint.intakes
    FOR EACH ROW EXECUTE FUNCTION mint.check_status('received',
      'received>checking,received>decided,checking>passed,checking>failed,checking>indeterminate,'
      'passed>decided,failed>decided,indeterminate>decided,passed>checking,indeterminate>checking,'
      'failed>checking');
