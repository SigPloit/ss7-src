/*
 * TeleStax, Open Source Cloud Communications  Copyright 2012.
 * and individual contributors
 * by the @authors tag. See the copyright.txt in the distribution for a
 * full listing of individual contributors.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package fuzzy;

import java.io.IOException;
import java.io.OutputStream;

import org.mobicents.protocols.asn.AsnException;
import org.mobicents.protocols.asn.AsnOutputStream;
import org.mobicents.protocols.asn.Tag;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.primitives.MAPAsnPrimitive;

/**
 *
 * @author amit bhayani
 * @author sergey vetyutnev
 *
 */
public abstract class FuzzyIMSIString implements MAPAsnPrimitive {

    protected static int DIGIT_1_MASK = 0x0F;
    protected static int DIGIT_2_MASK = 0xF0;

    protected String data;

    protected int minLength;
    protected int maxLength;
    protected String _PrimitiveName;

    public FuzzyIMSIString(int minLength, int maxLength, String _PrimitiveName) {
	this.minLength = minLength;
	this.maxLength = maxLength;
	this._PrimitiveName = _PrimitiveName;
    }

    public FuzzyIMSIString(int minLength, int maxLength, String _PrimitiveName, String data) {
	this(minLength, maxLength, _PrimitiveName);

	this.data = data;
    }

    public int getTag() throws MAPException {
	return Tag.STRING_OCTET;
    }

    public int getTagClass() {
	return Tag.CLASS_UNIVERSAL;
    }

    public boolean getIsPrimitive() {
	return true;
    }

    public void encodeAll(AsnOutputStream asnOs) throws MAPException {

	this.encodeAll(asnOs, this.getTagClass(), this.getTag());
    }

    public void encodeAll(AsnOutputStream asnOs, int tagClass, int tag) throws MAPException {

	try {
	    asnOs.writeTag(tagClass, this.getIsPrimitive(), tag);
	    int pos = asnOs.StartContentDefiniteLength();
	    this.encodeData(asnOs);
	    asnOs.FinalizeContent(pos);
	} catch (AsnException e) {
	    throw new MAPException("AsnException when encoding " + _PrimitiveName + ": " + e.getMessage(), e);
	}
    }

    public void encodeData(AsnOutputStream asnOs) throws MAPException {

	if (this.data == null)
	    throw new MAPException("Error while encoding the " + _PrimitiveName + ": data is not defined");

	char[] chars = this.data.toCharArray();
	for (int i = 0; i < chars.length; i = i + 2)
	    try {
		asnOs.write(chars[i]);
	    } catch (Exception e) {
		throw new MAPException("Error while encoding the string " + e.getMessage(), e);
	    }
    }

    public static void encodeString(OutputStream asnOs, String data) throws MAPException {
	char[] chars = data.toCharArray();
	for (int i = 0; i < chars.length; i = i + 2) {
	    try {
		asnOs.write(chars[i]);
	    } catch (IOException e) {
		throw new MAPException("Error when encoding TbcdString: " + e.getMessage(), e);
	    }
	}

    }

    public String toString() {
	return _PrimitiveName + " [" + this.data + "]";
    }

    public int hashCode() {
	final int prime = 31;
	int result = 1;
	result = prime * result + ((data == null) ? 0 : data.hashCode());
	return result;
    }

    public boolean equals(Object obj) {
	if (this == obj)
	    return true;
	if (obj == null)
	    return false;
	if (getClass() != obj.getClass())
	    return false;
	FuzzyIMSIString other = (FuzzyIMSIString) obj;
	if (data == null) {
	    if (other.data != null)
		return false;
	} else if (!data.equals(other.data))
	    return false;
	return true;
    }
}
